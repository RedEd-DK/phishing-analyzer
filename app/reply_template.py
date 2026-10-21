"""Email-safe, self-contained HTML and readable text for analysis responses."""
import html
from collections import OrderedDict
from urllib.parse import quote, urlsplit

from .investigation_report import TITLES, display
from .security_checks import PRIORITIES, host

BG = "#080e1c"
PANEL = "#101a2d"
CARD = "#152239"
LINE = "#26364e"
WHITE = "#edf4ff"
MUTED = "#b0bfd4"
CYAN = "#69e5df"
FONT = "font-family:Arial,Helvetica,sans-serif;"
PRIORITY_COLORS = {"high": "#ff9ca8", "medium": "#ffd18a", "low": "#9bc7ff", "informational": CYAN}


def esc(value, limit=320):
    text = display(value)
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return html.escape(text, quote=True)


def targets(report):
    def walk(items, prefix=""):
        for i, item in enumerate(items, 1):
            label = prefix + str(i)
            yield "Original email " + label, item
            yield from walk(item.get("originals", []), label + ".")
    return list(walk(report.get("originals", []))) or [("Submitted email", report)]


def priority_for(items):
    priorities = [item.get("assessment", {}).get("review_priority", "unavailable") for _, item in items]
    return max(priorities, key=lambda value: PRIORITIES.get(value, -1), default="unavailable")


def destinations(urls):
    groups = OrderedDict()
    for url in urls:
        hostname = host(url) or "Unrecognized destination"
        groups.setdefault(hostname, []).append(url)
    return groups


def compact_url(url):
    """Presentation only. Full URLs remain in stored evidence, never fetched."""
    try:
        parts = urlsplit(url)
        if host(url) is None:
            return display(url)[:100]
        path = parts.path
        if len(path) > 52:
            path = path[:49] + "…"
        # Include user-info if present so compacting cannot conceal that signal.
        compact = parts.scheme + "://" + parts.netloc + path
        if parts.query:
            compact += "?…"
        if parts.fragment:
            compact += "#…"
        return display(compact)[:160]
    except ValueError:
        return display(url)[:100]


def paragraph(text, size=14, color=MUTED, extra=""):
    return '<p style="margin:0;%sfont-size:%dpx;line-height:1.65;color:%s;%s">%s</p>' % (FONT, size, color, extra, text)


def label(text, color=CYAN):
    return paragraph(text, 10, color, "font-weight:700;letter-spacing:2px;text-transform:uppercase;")


def gap(height=18):
    return '<div style="height:%dpx;line-height:%dpx;font-size:1px;">&nbsp;</div>' % (height, height)


def table(content, background=None, extra=""):
    bgcolor = ' bgcolor="%s"' % background if background else ""
    if background:
        extra = "background-color:%s;" % background + extra
    return '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0"%s style="width:100%%;border-collapse:separate;border-spacing:0;%s">%s</table>' % (bgcolor, extra, content)


def box(content, background=CARD, padding=20, border=LINE):
    return table('<tr><td class="card-pad" style="padding:%dpx;border:1px solid %s;border-radius:12px;">%s</td></tr>' %
                 (padding, border, content), background, "border-radius:12px;")


def text_reply(report, config, reference=""):
    items = targets(report)
    attached = bool(report.get("originals"))
    lines = ["RED EDUCATION | EMAIL ANALYSIS", "Thank you for reporting this email.", "",
             "Coverage: " + ("Attached original available" if attached else "LIMITED — original email needed"),
             "Review priority: " + priority_for(items).upper(),
             "This is an initial assessment using offline checks, not a final phishing verdict."]
    if reference:
        lines.append("Report reference: " + reference)
    if not attached:
        lines.extend(["", "No attached original email was extracted. These checks cover the submitted email only; inline forwards do not preserve complete original headers.",
                      "For fuller analysis, send the original email as an .eml attachment. Outlook .msg files, encrypted content and archives are not decoded."])
    for title, item in items[:6]:
        lines.extend(["", title.upper(), "Subject: " + display(item.get("subject"))[:240],
                      ("Sender: " if attached else "Reporting sender: ") + display(item.get("from"))[:180]])
        assessment = item.get("assessment", {})
        findings = assessment.get("findings", [])
        lines.append("Review priority: " + assessment.get("review_priority", "unavailable").upper())
        if not assessment:
            lines.append("Assessment unavailable; a manual review is needed.")
        elif not findings:
            lines.append("No indicators were found by the current checks. This does not establish that the email is safe.")
        for finding in findings[:5]:
            lines.append("- " + TITLES.get(finding["code"], display(finding["code"])) + ": " + display(finding.get("detail"))[:350])
        if len(findings) > 5:
            lines.append("Additional findings are retained in the investigation report.")
        groups = destinations(item.get("urls", []))
        if groups:
            lines.append("Link destinations (defanged; reputation not checked):")
            for hostname, urls in list(groups.items())[:4]:
                lines.append("- " + hostname.replace(".", "[.]") + " | " + str(len(urls)) + " link(s) | " + compact_url(urls[0]))
            lines.append("Long paths and query strings are shortened here. Full URLs are retained in the investigation report.")
        attachments = item.get("attachments", [])
        if attachments:
            lines.append("Attachments (not scanned):")
            lines.extend("- " + display(a.get("name"))[:180] for a in attachments[:4])
    if len(items) > 6:
        lines.append("Additional original emails are available in the investigation report.")
    lines.extend(["", "NEED A DEEPER REVIEW?",
                  "If you need to escalate this further, forward this email thread and the original reported email to " + config.escalation_email + ".",
                  "This automated response does not automatically forward your report to Security.", "",
                  "UNTIL VERIFIED", "Do not open unexpected attachments, enter credentials, or act on unusual payment requests.", "",
                  "CHECK LIMITS", "Authentication header claims are unverified. Links have not been visited and attachments have not been malware-scanned."])
    return "\n".join(lines) + "\n"


def html_reply(report, config, reference=""):
    items = targets(report)
    attached = bool(report.get("originals"))
    priority = priority_for(items)
    accent = PRIORITY_COLORS.get(priority, MUTED)
    url_count = sum(len(item.get("urls", [])) for _, item in items)
    file_count = sum(len(item.get("attachments", [])) for _, item in items)
    status = "ORIGINAL EMAIL NEEDED" if not attached else "INITIAL ANALYSIS READY"
    status_color = "#ffd18a" if not attached else CYAN
    header = table('<tr><td style="padding:24px 30px;border-bottom:1px solid %s;">%s</td><td align="right" style="padding:24px 30px 24px 0;border-bottom:1px solid %s;">%s</td></tr>' %
                   (LINE, label("RED EDUCATION", WHITE), LINE, label("SECURITY / EMAIL TRIAGE", MUTED)))
    hero = (label("● &nbsp; " + status, status_color) + gap(18) +
            paragraph("Your report,<br>analyzed.", 38, WHITE, "font-weight:700;line-height:1.12;letter-spacing:-1.4px;") + gap(16) +
            paragraph("Thank you for reporting this email. Here’s what our initial checks found—and what to do next.", 15) + gap(24))
    cells = []
    for key, value, color, width in [("REVIEW PRIORITY", priority.capitalize(), accent, 48),
                                    ("LINKS OBSERVED", str(url_count), WHITE, 26),
                                    ("FILES ATTACHED", str(file_count), WHITE, 26)]:
        cells.append('<td width="%d%%" valign="top" style="width:%d%%;padding:16px 8px;border-top:1px solid %s;">%s%s%s</td>' %
                     (width, width, LINE, paragraph(key, 9, MUTED, "font-weight:700;letter-spacing:1px;"), gap(8), paragraph(esc(value), 17, color, "font-weight:700;")))
    hero += table('<tr>' + ''.join(cells) + '</tr>')
    hero += paragraph("Initial offline assessment · not a final phishing verdict", 11, MUTED, "padding-top:12px;")
    sections = [header, '<tr><td class="content-pad" style="padding:32px 30px;">' + hero]
    if not attached:
        content = (label("01 / IMPROVE ANALYSIS", "#ffd18a") + gap(10) +
                   paragraph("Send the original as an .eml attachment", 19, WHITE, "font-weight:700;") + gap(10) +
                   paragraph("We reviewed your submitted copy, but couldn’t extract an attached original. Inline forwards don’t preserve complete original headers. The sender below is the person who reported it.", 13) + gap(10) +
                   paragraph("Outlook .msg files, encrypted content and archives aren’t decoded by this service.", 12))
        sections.extend([gap(20), box(content, "#211e29", border="#65523d")])
    for index, (title, item) in enumerate(items[:6], 1):
        assessment = item.get("assessment", {})
        item_priority = assessment.get("review_priority", "unavailable")
        color = PRIORITY_COLORS.get(item_priority, MUTED)
        content = label(("02" if not attached else "%02d" % index) + " / " + esc(title), MUTED)
        content += gap(10) + paragraph(esc(item.get("subject"), 240), 20, WHITE, "font-weight:700;overflow-wrap:anywhere;word-break:break-word;")
        content += gap(10) + paragraph(("Original sender: " if attached else "Reporting sender: ") + esc(item.get("from"), 180), 12)
        content += gap(8) + paragraph("Review priority · " + esc(item_priority.capitalize()), 12, color, "font-weight:700;")
        content += gap(22) + label("WHAT STOOD OUT", WHITE)
        findings = assessment.get("findings", [])
        for finding in findings[:5]:
            finding_color = PRIORITY_COLORS.get(finding.get("priority"), MUTED)
            content += gap(14) + paragraph("<span style=\"color:%s;\">●</span> &nbsp; %s" %
                       (finding_color, esc(TITLES.get(finding["code"], finding["code"]), 120)), 14, WHITE, "font-weight:700;")
            content += paragraph(esc(finding.get("detail"), 350), 12, MUTED, "padding-top:5px;")
        if not assessment:
            content += gap(10) + paragraph("Assessment unavailable. A manual review is needed.", 13)
        elif not findings:
            content += gap(10) + paragraph("No indicators were found by the current checks. This does not establish that the email is safe.", 13)
        if len(findings) > 5:
            content += gap(10) + paragraph("Additional findings are retained in the investigation report.", 12)
        groups = destinations(item.get("urls", []))
        if groups:
            content += gap(24) + label("LINK DESTINATIONS", WHITE) + gap(8)
            content += paragraph("Defanged text only. Reputation and redirects have not been checked.", 12)
            for hostname, urls in list(groups.items())[:4]:
                domain = html.escape(hostname.replace(".", "[.]"))
                row = ('<tr><td style="padding:12px 0;border-bottom:1px solid %s;">%s%s</td><td width="60" align="right" valign="top" style="width:60px;min-width:60px;vertical-align:top;padding:12px 0 0 12px;white-space:nowrap;">%s</td></tr>' %
                      (LINE, paragraph(domain, 13, CYAN, "font-weight:700;overflow-wrap:anywhere;"),
                       paragraph(esc(compact_url(urls[0]), 160), 11, MUTED, "padding-top:5px;word-break:break-all;overflow-wrap:anywhere;"),
                       paragraph(str(len(urls)) + " link" + ("s" if len(urls) != 1 else ""), 11)))
                content += table(row)
            content += gap(10) + paragraph("Long paths and query strings are shortened. Full URLs are retained in the investigation report.", 11)
            if len(groups) > 4:
                content += paragraph("+ %d more destination(s) in the investigation report." % (len(groups) - 4), 11)
        attachments = item.get("attachments", [])
        if attachments:
            content += gap(24) + label("ATTACHMENTS / NOT SCANNED", WHITE)
            for attachment in attachments[:4]:
                content += gap(10) + paragraph(esc(attachment.get("name"), 180), 13, WHITE)
                content += paragraph(esc(attachment.get("content_type"), 100), 11)
            if len(attachments) > 4:
                content += paragraph("Additional file details are retained in the investigation report.", 11)
        sections.extend([gap(20), box(content)])
    if len(items) > 6:
        sections.extend([gap(12), paragraph("Additional original emails are available in the investigation report.", 12)])
    security = html.escape(config.escalation_email, quote=True)
    mailto = "mailto:" + quote(config.escalation_email, safe="@.")
    escalation = (label("HUMAN EXPERTISE / WHEN YOU NEED IT", CYAN) + gap(12) +
                  paragraph("Need a deeper review?", 24, WHITE, "font-weight:700;letter-spacing:-0.5px;") + gap(12) +
                  paragraph("Forward this email thread and the original reported email to <strong style=\"color:%s;\">%s</strong> if you need to escalate further." % (WHITE, security), 14) + gap(20) +
                  table('<tr><td align="center" bgcolor="%s" style="background-color:%s;border-radius:8px;padding:14px 20px;">'
                        '<a href="%s" style="%sfont-size:14px;color:#071c24;text-decoration:none;font-weight:700;display:block;">Contact Security</a></td></tr>' %
                        (CYAN, CYAN, html.escape(mailto, quote=True), FONT), extra="max-width:250px;") + gap(12) +
                  paragraph("Contact opens a new email. Forward this thread to include the analysis and attach the original. Nothing is escalated automatically.", 11))
    sections.extend([gap(20), box(escalation, "#102c36", border="#2b696c"), gap(24),
                     paragraph("UNTIL VERIFIED", 10, WHITE, "font-weight:700;letter-spacing:1.5px;"), gap(8),
                     paragraph("Avoid unexpected attachments, credential requests and unusual payments until independently verified.", 12), gap(20),
                     paragraph("CHECK LIMITS", 10, MUTED, "font-weight:700;letter-spacing:1.5px;"), gap(8),
                     paragraph("Authentication header claims are unverified. Links were not visited. Attachments were not malware-scanned. An informational priority does not mean the email is safe.", 11),
                     '</td></tr>'])
    footer = ('<tr><td style="padding:20px 30px;border-top:1px solid %s;">%s%s</td></tr>' %
             (LINE, label("RED EDUCATION · PHISHING ANALYZER", MUTED),
              paragraph("Automated triage" + (" &nbsp; / &nbsp; REF " + esc(reference, 20) if reference else ""), 10, MUTED, "padding-top:6px;")))
    # Header is a nested presentation table, wrapped in its own row for valid HTML.
    content = '<tr><td>' + sections[0] + '</td></tr>' + ''.join(sections[1:]) + footer
    document = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark">'
                '<title>Your reported email · Analysis</title><style>'
                '@media only screen and (max-width:520px){.content-pad{padding:24px 16px!important}.card-pad{padding:16px!important}}'
                '</style></head><body style="margin:0;padding:0;background-color:%s;">' % BG)
    document += '<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all;">'
    document += 'Your email analysis is ready. ' + ('Attach the original email for fuller analysis.' if not attached else 'Review the findings and next steps.') + '</div>'
    document += table('<tr><td align="center" style="padding:28px 12px;">'
                      '<!--[if mso]><table role="presentation" width="680" cellpadding="0" cellspacing="0"><tr><td><![endif]-->'
                      '<table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" bgcolor="%s" '
                      'style="width:100%%;max-width:680px;border-spacing:0;background-color:%s;border:1px solid %s;border-radius:16px;border-top:3px solid %s;">%s</table>'
                      '<!--[if mso]></td></tr></table><![endif]--></td></tr>' % (PANEL, PANEL, LINE, CYAN, content), BG)
    return document + '</body></html>'
