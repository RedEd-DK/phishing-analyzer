import contextlib
import io
import json
import os
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from app.auto_reply import build_response
from app.config import Config
from app.replies import main as replies_main
from app.reply_template import compact_url, html_reply, text_reply
from app.security_checks import enrich
from app.store import Store


def config():
    return Config("9070ef23-9a31-45a8-9b14-45111a4ebbbe", "3e16daef-f2ac-4761-86eb-2d80e04d9a7a", "test-only")


def sample():
    return enrich({"subject": "FW: Malicious?", "from": "Reporter <reporter@rededucation.com>",
                   "headers": [{"name": "From", "value": "reporter@rededucation.com"}],
                   "urls": ["https://mandrillapp.com/track/click/123/example.com?p=PRIVATE_TRACKING_TOKEN" + str(i) for i in range(8)] +
                           ["https://cdn.example.org/assets/image.png"],
                   "attachments": [{"name": "image.png", "content_type": "image/png", "bytes": 1000}], "originals": []})


class Audit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.links = []
        self.stack = []
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.links.extend(v for k, v in attrs if k == "href")
        assert not any(k.startswith("on") or k in ("src", "srcset", "action") for k, v in attrs)
        if tag in ("table", "tr", "td"):
            if tag == "tr":
                assert self.stack[-1] == "table"
            if tag == "td":
                assert self.stack[-1] == "tr"
            self.stack.append(tag)
    def handle_endtag(self, tag):
        if tag in ("table", "tr", "td"):
            assert self.stack.pop() == tag


class TemplateTests(unittest.TestCase):
    def test_limited_coverage_is_prominent_and_never_safe(self):
        content = html_reply(sample(), config())
        self.assertIn("ORIGINAL EMAIL NEEDED", content)
        self.assertIn("Send the original as an .eml attachment", content)
        self.assertIn("Reporting sender:", content)
        self.assertIn("does not mean the email is safe", content)
        self.assertIn("not a final phishing verdict", content)

    def test_tracking_urls_grouped_and_tokens_not_echoed(self):
        for content in (html_reply(sample(), config()), text_reply(sample(), config())):
            self.assertIn("mandrillapp[.]com", content)
            self.assertIn("8 links" if content.startswith("<!doctype") else "8 link(s)", content)
            self.assertNotIn("PRIVATE_TRACKING_TOKEN", content)
            self.assertIn("Full URLs are retained", content)
        self.assertEqual(compact_url("https://example.com/path?secret=123"), "hxxps://example[.]com/path?…")

    def test_html_injection_and_only_trusted_mailto(self):
        report = sample()
        report["subject"] = '<script>alert(1)</script>'
        report["from"] = '<img src="https://attacker.test/pixel">'
        report["attachments"][0]["name"] = '</td><iframe src="https://attacker.test">'
        report["assessment"]["findings"][0]["detail"] = '<a href="https://attacker.test">click</a>'
        content = html_reply(report, config())
        audit = Audit()
        audit.feed(content)
        self.assertFalse(set(audit.tags) & {"script", "img", "iframe", "form", "input", "object", "svg"})
        self.assertEqual(audit.links, ["mailto:security@rededucation.com"])
        self.assertEqual(audit.stack, [])
        self.assertIn("&lt;script&gt;", content)
        self.assertIn("Contact opens a new email", content)

    def test_valid_presentation_tables_for_multiple_originals(self):
        report = sample()
        report["originals"] = [sample(), sample()]
        content = html_reply(report, config())
        audit = Audit()
        audit.feed(content)
        self.assertEqual(audit.stack, [])
        self.assertIn("Original email 1", content)
        self.assertIn("Original email 2", content)
        self.assertNotIn("ORIGINAL EMAIL NEEDED", content)

    def test_missing_assessment_is_not_reported_as_clean(self):
        content = html_reply({"subject": "Unanalyzed"}, config())
        self.assertIn("Assessment unavailable", content)
        self.assertNotIn("No indicators were found", content)

    def test_large_message_bound_and_footer_survives(self):
        original = sample()
        original["subject"] = "x" * 10000
        original["assessment"]["findings"] *= 1000
        content = html_reply({"originals": [original] * 100}, config())
        self.assertLess(len(content.encode()), 90000)
        self.assertTrue(content.endswith('</body></html>'))
        self.assertIn("Additional original emails", content)
        self.assertIn("mailto:security@rededucation.com", content)

    def test_mime_alternatives_have_matching_reference_and_no_attachments(self):
        raw = build_response(sample(), config(), 'immutable-id', 'reporter@rededucation.com')
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(msg.get_content_type(), 'multipart/alternative')
        plain = msg.get_body(preferencelist=('plain',)).get_content()
        content = msg.get_body(preferencelist=('html',)).get_content()
        reference = plain.split('Report reference: ')[1].splitlines()[0]
        self.assertIn(reference, content)
        self.assertEqual(list(msg.iter_attachments()), [])
        self.assertEqual(msg['Auto-Submitted'], 'auto-replied')

    def test_outbox_preview_handles_html_and_legacy_plain(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder))
            raw = build_response(sample(), config(), 'one', 'reporter@rededucation.com')
            store.queue_reply(config().mailbox,'one','reporter@rededucation.com',raw,'pending',None)
            legacy = b'Content-Type: text/plain; charset=utf-8\r\nSubject: Legacy\r\n\r\nLegacy response'
            store.queue_reply(config().mailbox,'two','reporter@rededucation.com',legacy,'accepted',None)
            stdout = io.StringIO()
            with patch.dict(os.environ, {'DATA_DIR':folder}), patch('sys.argv',['app.replies']), contextlib.redirect_stdout(stdout):
                self.assertEqual(replies_main(),0)
            self.assertIn('Legacy response',stdout.getvalue())
            self.assertIn('RED EDUCATION | EMAIL ANALYSIS',stdout.getvalue())
            store.close()


if __name__ == '__main__':
    unittest.main()
