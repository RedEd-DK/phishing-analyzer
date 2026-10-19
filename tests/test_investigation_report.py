import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from email.message import EmailMessage
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from app.email_parser import analyze
from app.investigation_report import defang, render_html, render_text
from app.reports import main, save_output
from app.store import Store


def make_message():
    msg = EmailMessage()
    msg["From"] = "Service <service@example.com>"
    msg["Subject"] = "Harmless report scenario"
    msg.set_content("Routine update: https://example.com/update")
    return msg


def records(msg):
    return [{"received_at": "2026-10-19T12:06:00Z", "processed_at": "2026-10-19 12:06:30",
             "report": analyze(msg.as_bytes())}]


class ReportTests(unittest.TestCase):
    def test_normal_mail_and_honest_limitations(self):
        msg = make_message()
        msg["X-Opaque-Delivery-Trace"] = "OPAQUE_DELIVERY_BLOB"
        result = records(msg)
        for output in (render_text(result), render_html(result)):
            self.assertIn("Service", output)
            self.assertIn("2026-10-19T12:06:00Z", output)
            self.assertIn("2026-10-19 12:06:30", output)
            self.assertIn("hxxps://example[.]com/update", output)
            self.assertIn("Suggested investigator checks", output)
            self.assertIn("unverified", output)
        self.assertIn("Phishing verdict: Undetermined", render_text(result))
        self.assertNotIn("OPAQUE_DELIVERY_BLOB", render_text(result))
        self.assertIn("OPAQUE_DELIVERY_BLOB", render_html(result))

    def test_legitimate_reply_to_difference_keeps_context(self):
        msg = make_message()
        msg["Reply-To"] = "support@service-provider.example"
        text = render_text(records(msg))
        self.assertIn("Replies go to a different domain", text)
        self.assertIn("Legitimate services can do this", text)
        self.assertIn("known contact method", text)

    def test_misleading_link_and_inert_attachment_scenarios(self):
        msg = make_message()
        msg.add_alternative('<a href="https://example.org/actual">https://example.com/displayed</a>', subtype="html")
        msg.add_attachment(b"Harmless text only, not an executable", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
        result = records(msg)
        text = render_text(result)
        self.assertIn("Displayed link and destination domains differ", text)
        self.assertIn("Attachment has an executable or script extension", text)
        self.assertIn("invoice.pdf.exe", text)
        self.assertIn("approved malware scanning", text)
        self.assertIn("HIGH", text)
        self.assertNotIn("https://example.org/actual", text)

    def test_wrapper_and_nested_original_scopes(self):
        wrapper = make_message()
        wrapper.replace_header("Subject", "Employee report")
        original = make_message()
        original.replace_header("Subject", "Original suspect message")
        original["Reply-To"] = "reply@example.net"
        wrapper.add_attachment(original)
        text = render_text(records(wrapper))
        self.assertIn("REPORTING EMAIL", text)
        self.assertIn("ORIGINAL EMAIL 1", text)
        self.assertIn("Attached originals: 1", text)
        self.assertLess(text.index("REPORTING EMAIL"), text.index("ORIGINAL EMAIL 1"))

    def test_html_escapes_email_markup_and_has_no_active_links(self):
        report = {"subject": '<script>alert("test")</script>', "from": '<img src="https://remote.test/x">',
                  "urls": ['HtTpS://example.com/?q=<script>'],
                  "headers": [{"name": "X-Test", "value": '</pre><iframe src="https://remote.test">'}]}
        output = render_html([{"report": report}])
        class Tags(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags = []
            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)
        tags = Tags()
        tags.feed(output)
        self.assertFalse(set(tags.tags) & {"script", "iframe", "img", "a", "form"})
        self.assertIn("&lt;script&gt;", output)
        self.assertIn("Content-Security-Policy", output)
        self.assertIn("hxxps://example[.]com", output)

    def test_terminal_controls_and_bidi_are_visible(self):
        text = render_text([{"report": {"subject": "fake\x1b[31m\nREPORT 999\u202e", "headers": []}}])
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("\\u001b", text)
        self.assertIn("\\u202e", text)
        self.assertIn("\\u000aREPORT 999", text)
        self.assertEqual(defang("HtTp://EXAMPLE.com/path"), "hxxp://EXAMPLE[.]com/path")

    def test_empty_and_legacy_reports(self):
        self.assertIn("No saved email reports", render_html([]))
        self.assertIn("No saved email reports", render_text([]))
        self.assertIn("--reanalyze", render_text([{"report": {"subject": "legacy"}}]))

    def test_private_atomic_export_does_not_follow_output_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "report.html"
            protected = Path(folder) / "existing.txt"
            protected.write_text("unchanged")
            target.symlink_to(protected)
            save_output(target, "<html>report</html>")
            self.assertEqual(protected.read_text(), "unchanged")
            self.assertFalse(target.is_symlink())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_cli_readable_json_and_html_keep_evidence_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder))
            raw = make_message().as_bytes()
            store.save("p@example.test", {"id": "one", "receivedDateTime": "2026-10-19T12:06:00Z"}, raw, analyze(raw))
            before = store.db.execute("SELECT * FROM reports").fetchall()
            for flags in ([], ["--json"], ["--format", "html"]):
                stdout = io.StringIO()
                with patch.dict(os.environ, {"DATA_DIR": folder}), patch("sys.argv", ["app.reports"] + flags), contextlib.redirect_stdout(stdout):
                    self.assertEqual(main(), 0)
                output = stdout.getvalue()
                if flags == ["--json"]:
                    self.assertEqual(len(json.loads(output)), 1)
                elif "html" in flags:
                    self.assertTrue(output.startswith("<!doctype html>"))
                else:
                    self.assertIn("PHISHING INVESTIGATION REPORT", output)
            self.assertEqual(before, store.db.execute("SELECT * FROM reports").fetchall())
            store.close()


if __name__ == "__main__":
    unittest.main()
