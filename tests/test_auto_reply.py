import base64
import io
import tempfile
import time
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from urllib.error import HTTPError, URLError

from app.auto_reply import build_response, dispatch, eligibility, queue_report, response_body
from app.config import Config
from app.email_parser import analyze
from app.graph_client import GraphClient, SendError
from app.main import poll_once
from app.store import Store


def cfg(mode="send"):
    return Config("9070ef23-9a31-45a8-9b14-45111a4ebbbe", "3e16daef-f2ac-4761-86eb-2d80e04d9a7a",
                  "test-only", auto_reply_mode=mode)


def email():
    msg = EmailMessage()
    msg["From"] = "Reporter <reporter@rededucation.com>"
    msg["Subject"] = "Please investigate"
    msg["Message-ID"] = "<report-123@rededucation.com>"
    msg.set_content("Reported suspicious message")
    return msg


def metadata(mid="one", received="2099-01-01T00:00:00Z"):
    return {"id": mid, "receivedDateTime": received}


class ReplyTests(unittest.TestCase):
    def test_recipient_is_reporter_not_original_or_reply_to(self):
        outer = email()
        outer["Reply-To"] = "someone@external.example"
        original = EmailMessage()
        original["From"] = "attacker@example.org"
        original.set_content("https://example.org")
        outer.add_attachment(original)
        report = analyze(outer.as_bytes())
        recipient, reason = eligibility(report, cfg())
        self.assertEqual((recipient, reason), ("reporter@rededucation.com", None))
        reply = BytesParser(policy=policy.default).parsebytes(build_response(report, cfg(), "one", recipient))
        self.assertEqual(str(reply["To"]), "reporter@rededucation.com")
        self.assertIsNone(reply["Cc"])
        self.assertIsNone(reply["Bcc"])
        self.assertIn("forward this email thread and the original reported email to security@rededucation.com", reply.get_content())
        self.assertIn("attacker@example.org", reply.get_content())
        self.assertEqual(reply["In-Reply-To"], "<report-123@rededucation.com>")
        self.assertEqual(reply["Auto-Submitted"], "auto-replied")
        self.assertFalse(reply.is_multipart())

    def test_loop_bulk_bounce_and_suppression_headers(self):
        for key, value in [("Auto-Submitted", "auto-replied"), ("Auto-Submitted", "auto-generated; owner=email"),
                           ("Precedence", "bulk"), ("List-Id", "list.example"), ("Return-Path", "<>"),
                           ("X-Phishing-Analyzer-Reply", "1"), ("X-Auto-Response-Suppress", "All")]:
            msg = email()
            msg[key] = value
            with self.subTest(header=key):
                self.assertIsNotNone(eligibility(analyze(msg.as_bytes()), cfg())[1])
        msg = email()
        msg["Auto-Submitted"] = "no"
        self.assertIsNone(eligibility(analyze(msg.as_bytes()), cfg())[1])

    def test_external_service_security_noreply_and_ambiguous_senders(self):
        for sender in ("attacker@example.org", "phishing@rededucation.com", "security@rededucation.com",
                       "noreply@rededucation.com", "postmaster@rededucation.com", "a@rededucation.com, b@rededucation.com"):
            msg = email()
            msg.replace_header("From", sender)
            self.assertIsNotNone(eligibility(analyze(msg.as_bytes()), cfg())[1])

    def test_original_analysis_avoids_reporter_signature_noise(self):
        outer = email()
        outer.set_content("Signature http://signature.example")
        original = EmailMessage()
        original["From"] = "sender@example.com"
        original["Subject"] = "Original"
        original.set_content("https://example.com")
        outer.add_attachment(original)
        body = response_body(analyze(outer.as_bytes()), cfg())
        self.assertNotIn("signature", body)
        self.assertIn("Subject: Original", body)
        self.assertIn("hxxps://example[.]com", body)

    def test_missing_original_explains_analysis_limit(self):
        body = response_body(analyze(email().as_bytes()), cfg())
        self.assertIn("No attached original email was extracted", body)
        self.assertIn(".eml attachment", body)
        self.assertIn("not a final phishing verdict", body)

    def test_activation_prevents_backlog_and_invalid_times(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            report = analyze(email().as_bytes())
            for i, received in enumerate(("2000-01-01T00:00:00Z", "bad", "2099-01-01")):
                queue_report(store, cfg(), metadata(str(i), received), report, time.time())
            self.assertEqual([r[0] for r in store.db.execute("SELECT state FROM reply_outbox")], ["skipped"] * 3)
            store.close()

    def test_queue_is_idempotent_after_restart_and_claim_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            report = analyze(email().as_bytes())
            store = Store(Path(directory))
            queue_report(store, cfg(), metadata(), report, 0)
            raw = store.db.execute("SELECT mime FROM reply_outbox").fetchone()[0]
            store.close()
            store = Store(Path(directory))
            queue_report(store, cfg(), metadata(), report, 0)
            self.assertEqual(store.db.execute("SELECT count(*),mime FROM reply_outbox").fetchone(), (1, raw))
            self.assertTrue(store.claim_reply(cfg().mailbox, "one"))
            self.assertFalse(store.claim_reply(cfg().mailbox, "one"))
            store.recover_replies()
            self.assertEqual(store.db.execute("SELECT state FROM reply_outbox").fetchone()[0], "uncertain")
            store.close()

    def test_preview_does_not_send_and_success_is_not_repeated(self):
        class Client:
            calls = 0
            def send_mime(self, raw):
                self.calls += 1
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            queue_report(store, cfg(), metadata(), analyze(email().as_bytes()), 0)
            client = Client()
            dispatch(client, store, cfg("preview"))
            self.assertEqual(client.calls, 0)
            self.assertEqual(dispatch(client, store, cfg()), 0)
            self.assertEqual(dispatch(client, store, cfg()), 0)
            self.assertEqual(client.calls, 1)
            self.assertEqual(store.db.execute("SELECT state FROM reply_outbox").fetchone()[0], "accepted")
            store.close()

    def test_uncertain_does_not_retry_permission_block_can_retry_later(self):
        class Client:
            calls = 0
            def send_mime(self, raw):
                self.calls += 1
                raise SendError("test_network_result_unknown")
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            queue_report(store, cfg(), metadata(), analyze(email().as_bytes()), 0)
            client = Client()
            self.assertEqual(dispatch(client, store, cfg()), 1)
            dispatch(client, store, cfg())
            self.assertEqual(client.calls, 1)
            store.close()

    def test_rate_limit_delays_additional_replies(self):
        class Client:
            calls = 0
            def send_mime(self, raw):
                self.calls += 1
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            for i in range(2):
                queue_report(store, cfg(), metadata(str(i)), analyze(email().as_bytes()), 0)
            client = Client()
            dispatch(client, store, replace(cfg(), replies_per_hour=1))
            self.assertEqual(client.calls, 1)
            self.assertEqual(store.db.execute("SELECT count(*) FROM reply_outbox WHERE state='pending'").fetchone()[0], 1)
            store.close()

    def test_poll_saves_and_sends_without_reprocessing(self):
        class Client:
            config = cfg()
            reads = sends = 0
            def messages(self):
                return iter([metadata()])
            def mime(self, mid):
                self.reads += 1
                return email().as_bytes()
            def send_mime(self, raw):
                self.sends += 1
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            client = Client()
            self.assertEqual(poll_once(client, store, cfg().mailbox), 0)
            self.assertEqual(poll_once(client, store, cfg().mailbox), 0)
            self.assertEqual((client.reads, client.sends), (1, 1))
            store.close()


class Response(io.BytesIO):
    status = 202


class SendOpener:
    def __init__(self, failure=None):
        self.requests = []
        self.failure = failure
    def open(self, req, timeout):
        self.requests.append(req)
        if self.failure:
            raise self.failure
        return Response(b"")


class SendTests(unittest.TestCase):
    def client(self, opener):
        client = GraphClient(cfg(), opener)
        client.token = "test-token"
        client.expires = time.monotonic() + 300
        return client

    def test_send_uses_base64_mime_and_202(self):
        opener = SendOpener()
        self.client(opener).send_mime(b"test MIME")
        req = opener.requests[0]
        self.assertEqual(req.get_method(), "POST")
        self.assertTrue(req.full_url.endswith("/sendMail"))
        self.assertEqual(req.get_header("Content-type"), "text/plain")
        self.assertEqual(base64.b64decode(req.data), b"test MIME")

    def test_non_idempotent_send_never_blindly_retries(self):
        for error, state in ((URLError("connection dropped"), "uncertain"),
                             (HTTPError("test", 503, "unavailable", {}, io.BytesIO()), "uncertain"),
                             (HTTPError("test", 403, "denied", {}, io.BytesIO()), "blocked"),
                             (HTTPError("test", 429, "throttle", {"Retry-After": "600"}, io.BytesIO()), "retry")):
            opener = SendOpener(error)
            with self.subTest(state=state):
                with self.assertRaises(SendError) as raised:
                    self.client(opener).send_mime(b"test")
                self.assertEqual(raised.exception.state, state)
                self.assertEqual(len(opener.requests), 1)
                if state == "retry":
                    self.assertEqual(raised.exception.retry_seconds, 600)

    def test_mode_gate_prevents_send(self):
        opener = SendOpener()
        client = self.client(opener)
        client.config = cfg("preview")
        with self.assertRaises(SendError):
            client.send_mime(b"test")
        self.assertEqual(opener.requests, [])


if __name__ == "__main__":
    unittest.main()
