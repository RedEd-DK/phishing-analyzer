import argparse
import logging
import os
import signal
import threading

from .config import Config
from .email_parser import analyze
from .graph_client import GraphClient
from .store import Store

LOG = logging.getLogger(__name__)


def poll_once(client, store, mailbox, stopped=None):
    processed = failed = 0
    for message in client.messages():
        if stopped and stopped.is_set():
            break
        if store.contains(mailbox, message["id"]):
            continue
        try:
            raw = client.mime(message["id"])
            report = analyze(raw)
            store.save(mailbox, message, raw, report)
            processed += 1
        except Exception as exc:
            # Untrusted email content and request details must not enter logs.
            LOG.warning("Message processing failed (%s); will retry next poll", type(exc).__name__)
            failed += 1
    LOG.info("Poll complete: processed=%d failed=%d", processed, failed)
    return failed


def main():
    parser = argparse.ArgumentParser(description="Read-only phishing report collector")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
