import argparse
import logging
import os
import signal
import threading

from .config import Config
from .email_parser import analyze
from .graph_client import GraphClient
from .store import Store
from .auto_reply import dispatch, queue_report

LOG = logging.getLogger(__name__)


def poll_once(client, store, mailbox, stopped=None):
    processed = failed = 0
    config = getattr(client, "config", None)
    replying = config is not None and config.auto_reply_mode != "off"
    activation = store.reply_activation(mailbox) if replying else None
    for message in client.messages():
        if stopped and stopped.is_set():
            break
        try:
            if store.contains(mailbox, message["id"]):
                report = store.report(mailbox, message["id"]) if replying else None
            else:
                raw = client.mime(message["id"])
                report = analyze(raw)
                store.save(mailbox, message, raw, report)
                processed += 1
            if replying:
                queue_report(store, config, message, report, activation)
        except Exception as exc:
            # Untrusted email content and request details must not enter logs.
            LOG.warning("Message processing failed (%s); will retry next poll", type(exc).__name__)
            failed += 1
    if replying and not (stopped and stopped.is_set()):
        failed += dispatch(client, store, config)
    LOG.info("Poll complete: processed=%d failed=%d", processed, failed)
    return failed


def main():
    parser = argparse.ArgumentParser(description="Phishing analysis and reporting-sender response service")
    parser.add_argument("--once", action="store_true", help="Poll once then exit; failures return exit code 1")
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = Config.from_env()
    except (ValueError, TypeError):
        LOG.error("Invalid configuration. Check required variables and numeric limits in .env.example")
        return 2
    stopped = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stopped.set())
    store = Store(config.data_dir)
    import fcntl
    worker_lock = (config.data_dir / "worker.lock").open("a")
    try:
        fcntl.flock(worker_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        LOG.error("Another collector already owns this evidence volume; use one worker")
        worker_lock.close()
        store.close()
        return 2
    store.recover_replies()
    LOG.info("Automatic reply mode: %s", config.auto_reply_mode)
    client = GraphClient(config)
    try:
        while not stopped.is_set():
            try:
                failed = poll_once(client, store, config.mailbox, stopped)
            except Exception as exc:
                LOG.error("Poll failed (%s). Check connectivity and mailbox authorization", type(exc).__name__)
                failed = 1
            if args.once:
                return 1 if failed else 0
            stopped.wait(config.poll_seconds)
    finally:
        store.close()
        worker_lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
