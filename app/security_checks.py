"""Offline evidence-based indicators; never a phishing verdict or auth verifier."""
import ipaddress
import re
from email.utils import getaddresses
from pathlib import PurePosixPath
from urllib.parse import urlsplit

VERSION = 1
PRIORITIES = {"informational": 0, "low": 1, "medium": 2, "high": 3}
EXECUTABLE = {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
              ".js", ".jse", ".msi", ".lnk", ".hta", ".jar", ".app", ".sh"}
ACTIVE = {".docm", ".xlsm", ".pptm", ".xlam", ".html", ".htm", ".iso", ".img"}
ARCHIVES = {".zip", ".rar", ".7z", ".gz", ".tar"}


def host(url):
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        return parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except (ValueError, UnicodeError):
        return None


def addresses(values):
    return [address for _, address in getaddresses(values) if "@" in address]


def domain(address):
    try:
        return address.rsplit("@", 1)[1].rstrip(".").encode("idna").decode("ascii").lower()
    except (IndexError, UnicodeError):
        return ""


def assess(report):
    findings = []

    def add(code, priority, detail, evidence):
        findings.append({"code": code, "priority": priority, "detail": detail, "evidence": evidence})

    headers = {}
    for header in report.get("headers", []):
        headers.setdefault(header["name"].lower(), []).append(header["value"])
    sender = addresses(headers.get("from", []))
    reply = addresses(headers.get("reply-to", []))
    if len(sender) != 1 or len(headers.get("from", [])) != 1:
        add("sender_missing_or_ambiguous", "medium", "Expected one From header with one sender address.",
            headers.get("from", []))
    elif reply:
        different = [address for address in reply if domain(address) != domain(sender[0])]
        if different:
            add("reply_to_domain_mismatch", "medium",
                "Reply-To uses a different exact domain from From. Legitimate services can do this.",
                {"from": sender[0], "reply_to": different})
    if headers.get("reply-to") and not reply:
        add("reply_to_unparseable", "low", "Reply-To has no parseable email address.", headers["reply-to"])
    returns = addresses(headers.get("return-path", []))
    if len(sender) == 1 and any(domain(a) != domain(sender[0]) for a in returns):
        add("return_path_domain_mismatch", "informational",
            "Return-Path and From domains differ; common with mailing services. This is not a DMARC check.", returns)

    auth = []
    for value in headers.get("authentication-results", []):
        # Extract reported method tokens for display only; RFC 8601 comments and
        # forged headers make this unsuitable for authentication decisions.
        methods = [{"method": m.lower(), "result": r.lower()} for m, r in
                   re.findall(r"(?:^|;)\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b", value, re.I)]
        auth.append({"authserv_id": value.split(";", 1)[0].strip(),
                     "reported_results": methods, "raw": value, "trusted": False})
        if any(item["result"] in ("fail", "softfail", "permerror", "temperror") for item in methods):
            add("reported_authentication_failure", "informational",
                "An unverified header reports an authentication failure/error. Forwarded headers can be forged or synthetic.",
                methods)
    if not auth:
        add("authentication_results_missing", "informational",
            "No Authentication-Results header was supplied; authentication status is unknown.", [])

    for url in report.get("urls", []):
        hostname = host(url)
        if hostname is None:
            add("url_malformed", "low", "URL has no valid HTTP(S) hostname.", url)
            continue
        parts = urlsplit(url)
        if parts.username is not None or parts.password is not None:
            add("url_embedded_credentials", "medium", "URL contains user-info before the real hostname.", url)
        if parts.scheme.lower() == "http":
            add("url_unencrypted_http", "low", "URL uses unencrypted HTTP.", url)
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            add("url_ip_address", "medium", "URL uses an IP address instead of a domain name.", url)
        if any(label.startswith("xn--") for label in hostname.split(".")):
            add("url_internationalized_domain", "low",
                "URL contains an internationalized hostname; review its spelling. This alone is not malicious.",
                {"url": url, "ascii_hostname": hostname})
    for link in report.get("links", []):
        displayed = re.fullmatch(r"\s*(https?://\S+)\s*", link.get("text", ""), re.I)
        if displayed:
            shown_host, target_host = host(displayed.group(1)), host(link["target"])
            if shown_host and target_host and shown_host != target_host:
                add("link_display_target_mismatch", "medium",
                    "A displayed URL and its HTML link target use different exact hostnames.", link)

    for attachment in report.get("attachments", []):
        name = attachment.get("name") or ""
        suffixes = [s.lower() for s in PurePosixPath(name.replace("\\", "/")).suffixes]
        suffix = suffixes[-1] if suffixes else ""
        if suffix in EXECUTABLE:
            add("attachment_executable_extension", "high",
                "Attachment filename indicates executable, script, or shortcut content. File content is not verified.", attachment)
            if len(suffixes) > 1:
                add("attachment_double_extension", "high", "Executable attachment uses multiple filename extensions.", name)
        elif suffix in ACTIVE:
            add("attachment_active_content_extension", "medium",
                "Attachment may contain active content or a disk image; content was not scanned.", attachment)
        elif suffix in ARCHIVES:
            add("attachment_archive", "low", "Archive contents were not inspected.", attachment)
        if any(char in name for char in "\u202a\u202b\u202d\u202e\u202c\u2066\u2067\u2068\u2069"):
            add("attachment_direction_controls", "high", "Filename contains text direction controls that can obscure its extension.", name)
    if report.get("defects"):
        add("mime_parser_defects", "low", "The MIME parser reported message defects.", report["defects"])

    priority = max((item["priority"] for item in findings), key=PRIORITIES.get, default="informational")
    return {"version": VERSION, "verdict": "not_determined", "review_priority": priority,
            "authentication": {"verified": False, "headers": auth},
            "findings": findings,
            "limitations": ["Offline heuristics only; no finding proves phishing and absence of findings does not prove safety.",
                            "Authentication headers are unverified; no SPF, DKIM, DMARC, DNS or reputation validation.",
                            "Exact hostname/domain comparisons; no organizational-domain or public-suffix matching.",
                            "Attachments are classified by filename only; no malware scan or archive inspection."]}


def enrich(report):
    """Keep findings scoped to each message and aggregate review priority only."""
    for original in report.get("originals", []):
        enrich(original)
    report["assessment"] = assess(report)
    priorities = [report["assessment"]["review_priority"]] + [
        original["assessment"]["overall_review_priority"] for original in report.get("originals", [])]
    report["assessment"]["overall_review_priority"] = max(priorities, key=PRIORITIES.get)
    return report
