import base64
import io
import json
import os
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from app.config import Config
from app.email_parser import analyze
from app.graph_client import GRAPH, GraphClient, GraphError
from app.main import poll_once
from app.store import Store


def original():
    msg = EmailMessage()
    msg["From"] = "sender@example.test"
    msg["Subject"] = "Original"
    msg["Received"] = "first hop"
    msg["Received"] = "second hop"
    msg["Authentication-Results"] = "example.test; spf=fail"
    msg.set_content("Visit https://example.test/login.")
    return msg


def config():
    return Config("9070ef23-9a31-45a8-9b14-45111a4ebbbe",
                  "3e16daef-f2ac-4761-86eb-2d80e04d9a7a", "test-only")


class ParserTests(unittest.TestCase):
    def test_plain_and_duplicate_headers(self):
        result = analyze(original().as_bytes())
        self.assertEqual(result["urls"], ["https://example.test/login"])
        self.assertEqual(sum(h["name"] == "Received" for h in result["headers"]), 2)

    def test_html_actual_target_and_entities(self):
        msg = EmailMessage()
        msg.set_content('<a href="https://target.test/?a=1&amp;b=2">https://visible.test</a>', subtype="html")
        result = analyze(msg.as_bytes())
        self.assertIn("https://target.test/?a=1&b=2", result["urls"])
        self.assertIn("https://visible.test", result["urls"])

    def test_eml_file_and_rfc822(self):
        for attached in (original(), original().as_bytes()):
            with self.subTest(kind=type(attached).__name__):
                msg = EmailMessage()
                msg.set_content("Report https://reporter.test")
                if isinstance(attached, bytes):
                    msg.add_attachment(attached, maintype="application", subtype="octet-stream", filename="../../original.eml")
                else:
                    msg.add_attachment(attached)
                result = analyze(msg.as_bytes())
                self.assertEqual(len(result["originals"]), 1)
                self.assertEqual(result["originals"][0]["subject"], "Original")
                self.assertEqual(result["originals"][0]["urls"], ["https://example.test/login"])
                self.assertNotIn("https://example.test/login", result["urls"])

    def test_base64_rfc822(self):
        raw = (b"Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
               base64.encodebytes(original().as_bytes()))
        self.assertEqual(analyze(raw)["originals"][0]["subject"], "Original")

    def test_multiple_nested_originals(self):
        msg = EmailMessage()
        msg.set_content("Report")
        middle = EmailMessage()
        middle.set_content("Forward")
        middle.add_attachment(original())
        msg.add_attachment(middle)
        msg.add_attachment(original())
        report = analyze(msg.as_bytes())
        self.assertEqual(len(report["originals"]), 2)
        self.assertEqual(report["originals"][0]["originals"][0]["subject"], "Original")

    def test_binary_not_treated_as_body(self):
        msg = original()
        msg.add_attachment(b"https://binary.test", maintype="application", subtype="octet-stream", filename="payload.bin")
        report = analyze(msg.as_bytes())
        self.assertNotIn("https://binary.test", report["urls"])
        self.assertEqual(report["attachments"][0]["bytes"], 19)

    def test_invalid_charset(self):
        raw = b'Content-Type: text/plain; charset="no-such-charset"\n\nhttps://example.test'
        self.assertEqual(analyze(raw)["urls"], ["https://example.test"])

    def test_complexity_limits(self):
        msg = original()
        msg.add_attachment(original())
        with self.assertRaises(ValueError):
            analyze(msg.as_bytes(), max_depth=0)
        with self.assertRaises(ValueError):
            analyze(msg.as_bytes(), max_parts=1)


class StoreTests(unittest.TestCase):
    def test_idempotent_across_restart_and_raw_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder))
            raw = original().as_bytes()
            message = {"id": "immutable-id"}
            store.save("PHISHING@example.test", message, raw, analyze(raw))
            store.save("phishing@example.test", message, raw, analyze(raw))
            store.close()
            store = Store(Path(folder))
            self.assertTrue(store.contains("phishing@example.test", "immutable-id"))
            self.assertEqual(store.db.execute("SELECT count(*),raw_mime FROM reports").fetchone(), (1, raw))
            store.close()

    def test_failures_retry_and_do_not_block_other_messages(self):
        class Client:
            calls = []
            fail = True
            def messages(self):
                return iter([{"id": "one"}, {"id": "two"}])
            def mime(self, mid):
                self.calls.append(mid)
                if mid == "one" and self.fail:
                    raise GraphError("failure")
                return original().as_bytes()
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder))
            client = Client()
            self.assertEqual(poll_once(client, store, "p@example.test"), 1)
            self.assertFalse(store.contains("p@example.test", "one"))
            client.fail = False
            self.assertEqual(poll_once(client, store, "p@example.test"), 0)
            self.assertEqual(client.calls, ["one", "two", "one"])
            store.close()


class FakeOpener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []
    def open(self, req, timeout):
        self.requests.append(req)
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return io.BytesIO(value)


def token():
    return b'{"access_token":"fake-token","expires_in":3600}'


def http_error(code, headers=None):
    return HTTPError("https://graph.microsoft.com", code, "test", headers or {}, io.BytesIO(b""))


class GraphTests(unittest.TestCase):
    def test_auth_pagination_immutable_and_read_only(self):
        client = GraphClient(config(), FakeOpener([]))
        next_link = client.base + "/mailFolders/inbox/messages?$skip=100"
        opener = FakeOpener([token(), json.dumps({"value": [{"id": "1"}], "@odata.nextLink": next_link}).encode(),
                             b'{"value":[{"id":"2"}]}', b"raw MIME"])
        client.opener = opener
        self.assertEqual([m["id"] for m in client.messages()], ["1", "2"])
        self.assertEqual(client.mime("a/b"), b"raw MIME")
        self.assertIn("client_credentials", opener.requests[0].data.decode())
        self.assertIn("%2F", opener.requests[-1].full_url)
        for req in opener.requests[1:]:
            self.assertEqual(req.get_method(), "GET")
            self.assertEqual(req.get_header("Prefer"), 'IdType="ImmutableId"')
        self.assertEqual(len([r for r in opener.requests if r.get_method() == "POST"]), 1)

    def test_reject_external_pagination_before_auth(self):
        client = GraphClient(config(), FakeOpener([]))
        for url in ("https://attacker.test/", GRAPH + "/users/other@example.test/messages",
                    "http://graph.microsoft.com/v1.0/users/test/messages"):
            with self.assertRaises(GraphError):
                client.get(url)
        self.assertEqual(client.opener.requests, [])

    def test_throttling_then_success(self):
        delays = []
        client = GraphClient(config(), FakeOpener([token(), http_error(429, {"Retry-After": "2"}), b"ok"]), delays.append)
        self.assertEqual(client.mime("1"), b"ok")
        self.assertEqual(delays, [2])

    def test_long_retry_window_is_preserved(self):
        client = GraphClient(config(), FakeOpener([token(), http_error(429, {"Retry-After": "120"})]))
        with self.assertRaises(GraphError):
            client.mime("1")
        with self.assertRaises(GraphError):
            client.mime("1")
        self.assertEqual(len(client.opener.requests), 2)

    def test_unauthorized_refresh(self):
        opener = FakeOpener([token(), http_error(401), token(), b"ok"])
        client = GraphClient(config(), opener)
        self.assertEqual(client.mime("1"), b"ok")
        self.assertEqual(len(opener.requests), 4)

    def test_forbidden_safe_and_no_retry(self):
        opener = FakeOpener([token(), http_error(403)])
        client = GraphClient(config(), opener)
        with self.assertRaisesRegex(GraphError, "HTTP status 403"):
            client.mime("1")
        self.assertEqual(len(opener.requests), 2)

    def test_size_limit(self):
        cfg = config()
        client = GraphClient(cfg, FakeOpener([token(), b"x" * (cfg.max_message_bytes + 1)]))
        with self.assertRaisesRegex(GraphError, "size limit"):
            client.mime("1")

    def test_missing_credentials_and_secret_not_repr(self):
        with patch.dict(os.environ, {"CLIENT_SECRET": ""}, clear=True):
            with self.assertRaises(ValueError):
                Config.from_env()
        self.assertNotIn("test-only", repr(config()))


if __name__ == "__main__":
    unittest.main()
