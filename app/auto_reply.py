"""Build limited plain-text analysis responses and dispatch the durable outbox."""
import hashlib
import logging
import re
import time
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime, getaddresses
from datetime import timezone

from .graph_client import SendError
from .investigation_report import TITLES, display

LOG = logging.getLogger(__name__)


def values(report, name):
    return [h["value"] for h in report.get("headers", []) if h["name"].lower() == name.lower()]


def eligibility(report, config):
    """Use outer reporting sender only; never attached-original or Reply-To addresses."""
    parsed = [a for _, a in getaddresses(values(report, "From")) if a]
    if len(values(report, "From")) != 1 or len(parsed) != 1 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", parsed[0]):
        return None, "invalid_reporting_sender"
    recipient = parsed[0].lower()
    local, domain = recipient.rsplit("@", 1)
    if recipient in (config.mailbox.lower(), config.escalation_email.lower()):
        return None, "service_or_security_sender"
    if domain not in config.reporter_domains:
        return None, "reporter_domain_not_allowed"
    if re.search(r"^(?:no[-_]?reply|do[-_]?not[-_]?reply|mailer-daemon|postmaster)(?:[+._-]|$)", local):
        return None, "automated_sender_address"
    if values(report, "X-Phishing-Analyzer-Reply"):
        return None, "analyzer_reply"
    if any(value.split(";", 1)[0].strip().lower() != "no" for value in values(report, "Auto-Submitted")):
        return None, "auto_submitted"
    if any(value.strip().lower() in ("bulk", "list", "junk") for value in values(report, "Precedence")) or values(report, "List-Id"):
        return None, "bulk_or_list_message"
    if any(value.strip() == "<>" for value in values(report, "Return-Path")):
        return None, "bounce_return_path"
    if any("multipart/report" in value.lower() or "message/delivery-status" in value.lower() for value in values(report, "Content-Type")):
        return None, "delivery_status_message"
    if any(re.search(r"\b(all|autoreply|oof)\b", value, re.I) for value in values(report, "X-Auto-Response-Suppress")):
        return None, "automatic_response_suppressed"
    return recipient, None


def response_body(report, config):
    lines = ["Thank you for reporting this email.", "", "AUTOMATED ANALYSIS",
             "This is an initial assessment using offline checks, not a final phishing verdict.",
             "Authentication header claims are unverified. Links have not been visited and attachments have not been malware-scanned.", ""]
    # Focus on originals so a reporter's signature does not become the suspect evidence.
    def originals(items, prefix=""):
        for index, item in enumerate(items, 1):
            label = prefix + str(index)
            yield label, item
            yield from originals(item.get("originals", []), label + ".")
    targets = list(originals(report.get("originals", [])))
    if not targets:
        targets = [("Submitted email", report)]
        lines.extend(["No attached original email was extracted. These checks cover the submitted email only; inline forwards do not preserve complete original headers.",
                      "For fuller analysis, send the original email as an .eml attachment. Outlook .msg files, encrypted content and archives are not decoded.", ""])
    for label, item in targets[:20]:
        assessment = item.get("assessment", {})
        lines.extend(["Email " + label, "Subject: " + display(item.get("subject")),
                      "Sender: " + display(item.get("from")),
                      "Review priority: " + display(assessment.get("review_priority", "unavailable")).upper()])
        findings = assessment.get("findings", [])
        for finding in findings[:20]:
            lines.append("- " + TITLES.get(finding["code"], display(finding["code"])) + ": " + display(finding.get("detail")))
        if len(findings) > 20:
            lines.append("Additional findings are available in the saved investigation report.")
        if not findings:
            lines.append("No indicators were found by the current checks. This does not establish that the email is safe.")
        if item.get("urls"):
            lines.append("Extracted links (defanged):")
            lines.extend("- " + display(url) for url in item["urls"][:10])
        if item.get("attachments"):
            lines.append("Attachments (not scanned):")
            lines.extend("- " + display(a.get("name")) for a in item["attachments"][:10])
        lines.append("")
    body = "\n".join(lines)
    if len(body) > 28000:
        body = body[:28000] + "\n[Summary shortened; full evidence is retained in the investigation report.]\n"
    body += ("\nNEXT STEPS\nDo not open unexpected attachments, enter credentials, or act on unusual payment requests until verified.\n"
             "If you need to escalate this further, forward this email thread and the original reported email to " + config.escalation_email + ".\n"
             "This automated response does not automatically forward your report to Security.\n")
    return body


def build_response(report, config, message_id, recipient):
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"] = config.mailbox
    msg["To"] = recipient
    msg["Subject"] = "Analysis of your reported email: " + display(report.get("subject"))[:160]
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    marker = hashlib.sha256((config.mailbox.lower() + ":" + message_id).encode()).hexdigest()
    msg["Message-ID"] = "<analysis-" + marker + "@" + config.mailbox.rsplit("@", 1)[1] + ">"
    msg["Auto-Submitted"] = "auto-replied"
    msg["X-Auto-Response-Suppress"] = "All"
    msg["X-Phishing-Analyzer-Reply"] = "1"
    ids = values(report, "Message-ID")
    if len(ids) == 1 and re.fullmatch(r"<[^\s<>\x00-\x1f]+>", ids[0]):
        msg["In-Reply-To"] = ids[0]
        msg["References"] = ids[0]
    msg.set_content(response_body(report, config))
    return msg.as_bytes()


def queue_report(store, config, message, report, activation):
    if store.db.execute("SELECT 1 FROM reply_outbox WHERE mailbox=? AND message_id=?",
                        (config.mailbox.lower(), message["id"])).fetchone():
        return
    try:
        received = datetime.fromisoformat(message.get("receivedDateTime", "").replace("Z", "+00:00"))
        if received.tzinfo is None:
            raise ValueError("Missing timezone")
        before = received.timestamp() < activation
    except (ValueError, TypeError):
        store.queue_reply(config.mailbox, message["id"], None, None, "skipped", "invalid_receive_time")
        return
    if before:
        store.queue_reply(config.mailbox, message["id"], None, None, "skipped", "before_reply_activation")
        return
    recipient, reason = eligibility(report, config)
    if reason:
        store.queue_reply(config.mailbox, message["id"], None, None, "skipped", reason)
        return
    mime = build_response(report, config, message["id"], recipient)
    store.queue_reply(config.mailbox, message["id"], recipient, mime, "pending", None)


def dispatch(client, store, config):
    if config.auto_reply_mode != "send":
        return 0
    failed = 0
    jobs = store.db.execute("""SELECT message_id,recipient,mime FROM reply_outbox
        WHERE mailbox=? AND state IN ('pending','retry','blocked') AND next_attempt<=?
        ORDER BY created_at LIMIT 20""", (config.mailbox.lower(), time.time())).fetchall()
    for mid, recipient, mime in jobs:
        recent = store.db.execute("""SELECT count(*) FROM reply_outbox WHERE mailbox=? AND recipient=?
            AND state IN ('sending','accepted','uncertain') AND updated_at>?""",
            (config.mailbox.lower(), recipient, time.time() - 3600)).fetchone()[0]
        if recent >= config.replies_per_hour:
            continue
        if not store.claim_reply(config.mailbox, mid):
            continue
        try:
            client.send_mime(mime)
        except SendError as exc:
            store.finish_reply(config.mailbox, mid, exc.state, str(exc), exc.retry_seconds)
            LOG.warning("Analysis reply status=%s reason=%s", exc.state, str(exc))
            failed += 1
        except Exception:
            store.finish_reply(config.mailbox, mid, "uncertain", "unexpected_send_result")
            LOG.warning("Analysis reply outcome uncertain; manual Sent Items review required")
            failed += 1
        else:
            store.finish_reply(config.mailbox, mid, "accepted", "graph_accepted_not_delivery_confirmation")
            LOG.info("Analysis reply accepted by Microsoft Graph")
    return failed
