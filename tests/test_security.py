import json
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from app.email_parser import analyze
from app.reports import reanalyze, summary
from app.security_checks import enrich
from app.store import Store


def message():
    msg = EmailMessage()
    msg["From"] = "Sender <sender@example.com>"
    msg.set_content("Safe example https://example.com")
    return msg


def codes(report):
    return {finding["code"] for finding in report["assessment"]["findings"]}


class SecurityTests(unittest.TestCase):
    def test_plain_message_is_not_certified_safe(self):
        report = analyze(message().as_bytes())
        self.assertEqual(report["assessment"]["verdict"], "not_determined")
        self.assertEqual(report["assessment"]["review_priority"], "informational")
        self.assertIn("authentication_results_missing", codes(report))

    def test_reply_to_mismatch_and_case_normalization(self):
        msg = message()
        msg["Reply-To"] = "reply@EXAMPLE.COM"
        self.assertNotIn("reply_to_domain_mismatch", codes(analyze(msg.as_bytes())))
        msg.replace_header("Reply-To", "reply@example.net")
        self.assertIn("reply_to_domain_mismatch", codes(analyze(msg.as_bytes())))

    def test_missing_and_ambiguous_from(self):
        for headers in ([], [{"name": "From", "value": "a@example.com, b@example.net"}],
                        [{"name": "From", "value": "a@example.com"}] * 2):
            report = enrich({"headers": headers})
            self.assertIn("sender_missing_or_ambiguous", codes(report))

    def test_authentication_pass_or_fail_never_trusted(self):
        msg = message()
        msg["Authentication-Results"] = "forged.test; spf=pass; dkim=pass; dmarc=pass"
        result = analyze(msg.as_bytes())["assessment"]
        self.assertFalse(result["authentication"]["verified"])
        self.assertFalse(result["authentication"]["headers"][0]["trusted"])
        msg.replace_header("Authentication-Results", "synthetic.test; spf=fail; dkim=none; dmarc=fail")
        result = analyze(msg.as_bytes())
        self.assertIn("reported_authentication_failure", codes(result))
        self.assertEqual(result["assessment"]["review_priority"], "informational")

    def test_repeated_authentication_headers_preserved(self):
        report = enrich({"headers": [{"name": "Authentication-Results", "value": value}
                         for value in ("a.test; spf=pass", "b.test; dmarc=fail")]})
        self.assertEqual(len(report["assessment"]["authentication"]["headers"]), 2)

    def test_link_target_mismatch_with_nested_markup(self):
        msg = message()
        msg.add_alternative('<a href="https://example.org/path?a=1&amp;b=2"><b>https://example.com/shown</b></a>', subtype="html")
        report = analyze(msg.as_bytes())
        finding = next(f for f in report["assessment"]["findings"] if f["code"] == "link_display_target_mismatch")
        self.assertEqual(finding["evidence"]["target"], "https://example.org/path?a=1&b=2")
        self.assertEqual(finding["evidence"]["text"], "https://example.com/shown")

    def test_matching_hostname_and_friendly_text_no_mismatch(self):
        msg = message()
        msg.add_alternative('<a href="https://EXAMPLE.COM/actual">https://example.com/displayed</a>'
                            '<a href="https://other.test">Click here</a>', subtype="html")
        self.assertNotIn("link_display_target_mismatch", codes(analyze(msg.as_bytes())))

    def test_url_indicators_and_malformed_url(self):
        report = enrich({"urls": ["http://user@192.0.2.1/login", "https://[::1]/", "http://[broken",
                                   "https://xn--bcher-kva.example/", "https://bücher.example/"]})
        self.assertTrue({"url_embedded_credentials", "url_ip_address", "url_unencrypted_http",
                         "url_malformed", "url_internationalized_domain"}.issubset(codes(report)))

    def test_attachment_indicators_and_case(self):
        report = enrich({"attachments": [{"name": name} for name in
                         ("invoice.pdf.EXE", "report.docm", "archive.zip", "photo\u202egnp.exe")]})
        self.assertTrue({"attachment_executable_extension", "attachment_double_extension",
                         "attachment_active_content_extension", "attachment_archive",
                         "attachment_direction_controls"}.issubset(codes(report)))
        self.assertEqual(report["assessment"]["review_priority"], "high")

    def test_normal_attachment_no_extension_warning(self):
        msg = message()
        msg.add_attachment(b"test", maintype="application", subtype="pdf", filename="report.pdf")
        self.assertFalse(any(code.startswith("attachment_") for code in codes(analyze(msg.as_bytes()))))

    def test_original_scope_and_aggregate_priority(self):
        wrapper = message()
        nested = message()
        nested.add_attachment(b"not executable test bytes", maintype="application", subtype="octet-stream", filename="test.exe")
        wrapper.add_attachment(nested)
        report = analyze(wrapper.as_bytes())
        self.assertNotIn("attachment_executable_extension", codes(report))
        self.assertIn("attachment_executable_extension", codes(report["originals"][0]))
        self.assertEqual(report["assessment"]["review_priority"], "informational")
        self.assertEqual(report["assessment"]["overall_review_priority"], "high")
        self.assertEqual(summary(report)["originals"][0]["assessment"]["review_priority"], "high")

    def test_reanalysis_preserves_raw_timestamp_and_deduplication(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder))
            raw = message().as_bytes()
            store.save("p@example.test", {"id": "one"}, raw, {"subject": "legacy report"})
            before = store.db.execute("SELECT raw_mime,processed_at FROM reports").fetchone()
            self.assertEqual(reanalyze(store.db), {"updated": 1, "failed": 0})
            first = store.db.execute("SELECT report_json FROM reports").fetchone()[0]
            self.assertIn("assessment", json.loads(first))
            self.assertEqual(reanalyze(store.db), {"updated": 1, "failed": 0})
            self.assertEqual(first, store.db.execute("SELECT report_json FROM reports").fetchone()[0])
            self.assertEqual(before, store.db.execute("SELECT raw_mime,processed_at FROM reports").fetchone())
            self.assertTrue(store.contains("p@example.test", "one"))
            store.close()

    def test_reanalysis_failure_preserves_existing_record(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder))
            store.save("p@example.test", {"id": "one"}, message().as_bytes(), {"subject": "legacy"})
            with patch("app.reports.analyze", side_effect=ValueError("test failure")):
                self.assertEqual(reanalyze(store.db), {"updated": 0, "failed": 1})
            self.assertEqual(json.loads(store.db.execute("SELECT report_json FROM reports").fetchone()[0]), {"subject": "legacy"})
            store.close()


if __name__ == "__main__":
    unittest.main()
