"""Portable investigator reports. No remote resources, scripts, or live links."""
import html
import json
import re
import unicodedata
from datetime import datetime, timezone


TITLES = {
    "sender_missing_or_ambiguous": "Sender is missing or ambiguous",
    "reply_to_domain_mismatch": "Replies go to a different domain",
    "reply_to_unparseable": "Reply address could not be read",
    "return_path_domain_mismatch": "Delivery return address uses another domain",
    "reported_authentication_failure": "Header reports an authentication failure",
    "authentication_results_missing": "Authentication results are unavailable",
    "url_malformed": "Link address could not be read",
    "url_embedded_credentials": "Link contains user information before its hostname",
    "url_unencrypted_http": "Link uses unencrypted HTTP",
    "url_ip_address": "Link points to an IP address",
    "url_internationalized_domain": "Link uses an internationalized domain",
    "link_display_target_mismatch": "Displayed link and destination domains differ",
    "attachment_executable_extension": "Attachment has an executable or script extension",
    "attachment_double_extension": "Executable filename has multiple extensions",
    "attachment_active_content_extension": "Attachment may contain active content",
    "attachment_archive": "Archive contents have not been inspected",
    "attachment_direction_controls": "Filename contains text direction controls",
    "mime_parser_defects": "Message formatting has parser warnings",
}
NOTE = ("Review priorities come from offline indicators, not a phishing verdict. "
        "No warnings does not establish safety. Authentication headers are unverified, "
        "and attachments have not been scanned. Links below are defanged for review.")


def defang(text):
    return re.sub(r"https?://[^\s<>\"']+",
                  lambda m: ("hxxps://" if m.group(0).lower().startswith("https://") else "hxxp://")
                  + m.group(0).split("://", 1)[1].replace(".", "[.]"),
                  str(text), flags=re.I)


def display(value):
    text = "Not supplied" if value is None or value == "" else str(value)
    text = "".join("\\u%04x" % ord(c) if unicodedata.category(c).startswith("C") else c for c in text)
    return defang(text)


def evidence(value):
    # JSON escapes controls inside source strings while retaining readable layout.
    return defang(json.dumps(value, indent=2, ensure_ascii=True))


def text_evidence(value):
    if isinstance(value, dict):
        return "\n".join(display(str(k).replace("_", " ").capitalize()) + ": " + text_evidence(v)
                         for k, v in value.items())
    if isinstance(value, list):
        return "; ".join(text_evidence(item) for item in value) or "None supplied"
    return display(value)


def header_values(report, name):
    return [h["value"] for h in report.get("headers", []) if h["name"].lower() == name.lower()]


def metadata(report):
    return [("Subject", report.get("subject")), ("Sender", report.get("from")),
            ("Reply-To", "; ".join(header_values(report, "Reply-To"))),
            ("Return-Path", "; ".join(header_values(report, "Return-Path"))),
            ("Date header (unverified)", "; ".join(header_values(report, "Date"))),
            ("Message-ID", "; ".join(header_values(report, "Message-ID")))]


def recommendations(report):
    codes = {f["code"] for f in report.get("assessment", {}).get("findings", [])}
    checks = []
    if any(c.startswith(("sender_", "reply_to_", "return_path_")) for c in codes):
        checks.append("Confirm the sender and reply destination through a known contact method. Mailing services can legitimately use different domains.")
    if any(c.startswith(("url_", "link_")) for c in codes):
        checks.append("Compare the real destination with the claimed organization. Use approved investigation tools for reputation and redirect checks; avoid opening the link directly.")
    if any(c.startswith("attachment_") for c in codes):
        checks.append("Review attachment type and business context, and use your approved malware scanning or sandbox process before opening it. Filename extensions do not verify file contents.")
    checks.append("Validate authentication using trusted mail gateway or Microsoft 365 evidence. Forwarded Authentication-Results headers can be forged or synthetic.")
    checks.append("Review the original request and business context before deciding whether to escalate or close the report.")
    if not report.get("originals") and report.get("source") == "report":
        checks.append("No attached original was extracted. If this was an inline forward, obtain the original email as an .eml attachment to inspect its headers.")
    return checks


def walk_messages(report, label="Reporting email"):
    yield label, report
    for i, original in enumerate(report.get("originals", []), 1):
        child_label = "Original email %d" % i if label == "Reporting email" else label + " / nested original %d" % i
        yield from walk_messages(original, child_label)


def render_text(records):
    lines = ["PHISHING INVESTIGATION REPORT", NOTE, ""]
    if not records:
        lines.append("No saved email reports were found.")
    for index, record in enumerate(records, 1):
        report = record["report"]
        overall = report.get("assessment", {}).get("overall_review_priority", "unavailable")
        lines.extend(["=" * 68, "REPORT %d | Overall review priority: %s" % (index, display(overall).upper()),
                      "Received by reporting mailbox (UTC): " + display(record.get("received_at")),
                      "Saved for investigation (UTC): " + display(record.get("processed_at")),
                      "Attached originals: %d" % len(report.get("originals", []))])
        if report.get("ai_analysis"):
            from .decision import ai_notes, decision_record
            lines.extend(["Combined result: " + decision_record(report)["result"],
                          *[display(note) for note in ai_notes(report)],
                          "AI usage: " + text_evidence(report["ai_analysis"].get("usage", {}))])
        for label, message in walk_messages(report):
            assessment = message.get("assessment", {})
            lines.extend(["", label.upper(), "Review priority: " + display(assessment.get("review_priority", "unavailable")),
                          "Phishing verdict: Undetermined"])
            lines.extend(key + ": " + display(value) for key, value in metadata(message))
            lines.append("\nFindings")
            for finding in assessment.get("findings", []):
                lines.extend(["- [%s] %s" % (display(finding.get("priority")).upper(),
                                             TITLES.get(finding["code"], display(finding["code"]))),
                              "  " + display(finding.get("detail")), "  Evidence: " + text_evidence(finding.get("evidence"))])
            if not assessment:
                lines.append("Analysis unavailable. Run app.reports --reanalyze to refresh this saved report.")
            elif not assessment.get("findings"):
                lines.append("No indicators were found by the current checks; this does not establish safety.")
            lines.extend(["\nExtracted URLs (defanged)"] + ["- " + display(u) for u in message.get("urls", [])])
            if not message.get("urls"):
                lines.append("None extracted.")
            lines.append("\nAttachments")
            lines.extend("- " + text_evidence(a) for a in message.get("attachments", []))
            if not message.get("attachments"):
                lines.append("No non-email attachments extracted. Attached emails are shown separately.")
            lines.append("\nAuthentication evidence (unverified)")
            auth = header_values(message, "Authentication-Results")
            lines.extend(display(a) for a in auth)
            if not auth:
                lines.append("No Authentication-Results header supplied.")
            lines.extend(["\nSuggested investigator checks"] + ["- " + check for check in recommendations(message)])
            lines.extend(["\nComplete preserved headers are available in the HTML report or with --json.",
                          "Evidence SHA-256: " + display(message.get("sha256"))])
        lines.append("")
    return "\n".join(lines) + "\n"


CSS = """
:root{font-family:system-ui,-apple-system,sans-serif;color:#20313e;background:#eef2f5}
*{box-sizing:border-box}body{margin:0;padding:32px 20px}main{max-width:1100px;margin:auto}
header{background:#173b4c;color:white;padding:30px;border-radius:16px}h1{margin:6px 0 14px;font-size:32px}
.eyebrow{text-transform:uppercase;letter-spacing:.15em;font-size:12px;font-weight:700}p{line-height:1.6}
.notice{padding:18px 24px;background:#fff6de;border-left:4px solid #b87916;border-radius:8px;margin:20px 0}
.report{background:white;border:1px solid #d4dfe5;border-radius:14px;padding:26px;margin:24px 0}
.report-top{display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.badge{display:inline-block;border-radius:30px;background:#edf1f4;padding:7px 13px;font-weight:700;font-size:13px}
.medium{background:#fff0cc;color:#795000}.high{background:#ffe2df;color:#8b2422}.low{background:#e4edf8;color:#254e7b}
h2{font-size:23px;margin:8px 0}h3{font-size:19px;margin:26px 0 12px}h4{font-size:15px;margin:5px 0 12px}
.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:20px 0}
.field{background:#f5f8fa;padding:13px;border-radius:8px;overflow-wrap:anywhere}.label{font-size:12px;color:#536875;display:block;margin-bottom:6px}
.message{border-top:1px solid #d8e2e8;margin-top:25px;padding-top:6px}.finding{border:1px solid #dce4e9;border-radius:10px;padding:16px;margin:12px 0}
.finding p{margin:10px 0}pre,code{font-family:ui-monospace,monospace;font-size:12px;overflow-wrap:anywhere;white-space:pre-wrap}
pre{background:#f5f8fa;border-radius:8px;padding:14px;max-width:100%}li{line-height:1.6;margin:7px 0;overflow-wrap:anywhere}
summary{cursor:pointer;font-weight:600;margin:15px 0}.muted,footer{color:#536875;font-size:13px}footer{padding:10px}
@media(max-width:650px){body{padding:14px 10px}.meta{grid-template-columns:1fr}.report,header{padding:18px}h1{font-size:26px}}
@media print{body{background:white;padding:0}.report{break-before:page;border:0}.report:first-of-type{break-before:auto}pre{font-size:10px}.finding{break-inside:avoid}}
"""


def render_html(records):
    esc = lambda v: html.escape(display(v), quote=True)
    pre = lambda v: "<pre>" + html.escape(evidence(v), quote=True) + "</pre>"

    def badge(priority):
        style = priority if priority in ("low", "medium", "high") else "informational"
        return '<span class="badge %s">%s review priority</span>' % (style, esc(priority).capitalize())

    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
             '<title>Email investigation reports</title><style>' + CSS + '</style></head><body><main>',
             '<header><div class="eyebrow">Phishing analyzer · Investigator workspace</div>',
             '<h1>Email investigation reports</h1><p>Evidence, review priorities, and suggested checks for %d saved report(s).</p></header>' % len(records),
             '<aside class="notice">' + esc(NOTE) + '</aside>']
    if not records:
        parts.append('<section class="report"><h2>No saved email reports</h2><p>Process an email before generating this report.</p></section>')
    for index, record in enumerate(records, 1):
        report = record["report"]
        overall = report.get("assessment", {}).get("overall_review_priority", "unavailable")
        parts.extend(['<section class="report"><div class="report-top"><div><div class="eyebrow">Report %d</div><h2>%s</h2></div>%s</div>' %
                      (index, esc(report.get("subject")), badge(overall)),
                      '<p class="muted">Received by reporting mailbox (UTC): %s<br>Saved for investigation (UTC): %s<br>Attached originals: %d</p>' %
                      (esc(record.get("received_at")), esc(record.get("processed_at")), len(report.get("originals", [])))])
        if report.get("ai_analysis"):
            from .decision import ai_notes, decision_record
            parts.append('<h3>Combined result: %s</h3>' % esc(decision_record(report)["result"]))
            parts.extend('<p>%s</p>' % esc(note) for note in ai_notes(report))
            parts.append('<p>AI usage: %s</p>' % esc(text_evidence(report["ai_analysis"].get("usage", {}))))
        for label, message in walk_messages(report):
            assessment = message.get("assessment", {})
            parts.append('<article class="message"><div class="report-top"><h3>%s</h3>%s</div>' %
                         (esc(label), badge(assessment.get("review_priority", "unavailable"))))
            parts.append('<p class="muted">Phishing verdict: undetermined. Findings below belong to this email.</p><div class="meta">')
            parts.extend('<div class="field"><span class="label">%s</span>%s</div>' % (esc(k), esc(v)) for k, v in metadata(message))
            parts.append('</div><h3>Findings and reasons</h3>')
            for finding in assessment.get("findings", []):
                parts.extend(['<div class="finding"><h4>%s</h4>%s<p>%s</p><details><summary>Supporting evidence</summary>%s</details></div>' %
                              (esc(TITLES.get(finding["code"], finding["code"])), badge(finding.get("priority", "informational")),
                               esc(finding.get("detail")), pre(finding.get("evidence")))])
            if not assessment:
                parts.append('<p>Analysis unavailable. Run app.reports --reanalyze to refresh this saved report.</p>')
            elif not assessment.get("findings"):
                parts.append('<p>No indicators found by the current checks. This does not establish safety.</p>')
            parts.append('<h3>Extracted URLs</h3><p class="muted">Defanged text; these are not clickable links.</p><ul>')
            parts.extend('<li><code>%s</code></li>' % esc(u) for u in message.get("urls", []))
            parts.append('</ul>' if message.get("urls") else '</ul><p>None extracted.</p>')
            parts.append('<h3>Attachments</h3>')
            parts.extend(pre(a) for a in message.get("attachments", []))
            if not message.get("attachments"):
                parts.append('<p>No non-email attachments extracted. Attached emails are shown separately.</p>')
            parts.append('<h3>Authentication evidence</h3><p>Unverified header claims; no independent SPF, DKIM, or DMARC validation.</p>')
            auth = header_values(message, "Authentication-Results")
            parts.extend('<pre>%s</pre>' % esc(a) for a in auth)
            if not auth:
                parts.append('<p>No Authentication-Results header supplied.</p>')
            parts.append('<h3>Suggested investigator checks</h3><ol>')
            parts.extend('<li>%s</li>' % esc(check) for check in recommendations(message))
            parts.extend(['</ol><details><summary>Preserved headers and evidence fingerprint</summary>',
                          pre(message.get("headers", [])), '<p class="muted">SHA-256: %s</p></details></article>' % esc(message.get("sha256"))])
        parts.append('</section>')
    parts.append('<footer>Generated at %s UTC. Local evidence report · no external resources or automated actions.</footer></main></body></html>' %
                 datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
    return "\n".join(parts)
