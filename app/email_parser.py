"""Parse untrusted MIME without executing attachments or fetching URLs."""
import base64
import hashlib
import quopri
import re
from email import policy
from email.parser import BytesParser
from html import unescape
from html.parser import HTMLParser

from .security_checks import enrich

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.values = []
        self.links = []
        self.anchor = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.finish_anchor()
            target = dict(attrs).get("href")
            if target and target.lower().startswith(("http://", "https://")):
                self.anchor = {"target": target, "text": ""}
        for name, value in attrs:
            if name in ("href", "src", "action") and value and value.lower().startswith(("http://", "https://")):
                self.values.append(value)

    def handle_data(self, data):
        if self.anchor is not None:
            self.anchor["text"] += data

    def handle_endtag(self, tag):
        if tag == "a":
            self.finish_anchor()

    def finish_anchor(self):
        if self.anchor is not None:
            self.links.append(self.anchor)
            self.anchor = None


def analyze(raw, max_depth=8, max_parts=1000):
    """Return report plus each attached original, preserving duplicate headers."""
    budget = [max_parts]

    def parse(data, depth, source):
        if depth > max_depth:
            raise ValueError("MIME nesting limit exceeded")
        message = BytesParser(policy=policy.default).parsebytes(data)
        result = {"source": source, "sha256": hashlib.sha256(data).hexdigest(),
                  "headers": [{"name": k, "value": str(v)} for k, v in message.items()],
                  "subject": str(message.get("Subject", "")),
                  "from": str(message.get("From", "")), "urls": [], "links": [],
                  "attachments": [], "originals": [],
                  "defects": [type(d).__name__ for d in message.defects]}
        urls = set()

        def walk(part, level):
            budget[0] -= 1
            if level > max_depth or budget[0] < 0:
                raise ValueError("MIME complexity limit exceeded")
            kind = part.get_content_type()
            filename = part.get_filename()
            if kind == "message/rfc822":
                encoding = str(part.get("Content-Transfer-Encoding", "")).lower()
                children = part.get_payload()
                if encoding in ("base64", "quoted-printable"):
                    # Python represents encoded message/rfc822 as a child message
                    # whose payload still contains the transfer-encoded original.
                    encoded = children[0].as_bytes(policy=policy.SMTP).strip()
                    nested = base64.b64decode(encoded) if encoding == "base64" else quopri.decodestring(encoded)
                    result["originals"].append(parse(nested, level + 1, filename or "attached-message.eml"))
                else:
                    for child in children if isinstance(children, list) else []:
                        result["originals"].append(parse(child.as_bytes(policy=policy.SMTP), level + 1,
                                                         filename or "attached-message.eml"))
                return
            if filename and filename.lower().endswith(".eml"):
                result["originals"].append(parse(part.get_payload(decode=True) or b"", level + 1, filename))
                return
            if part.is_multipart():
                for child in part.iter_parts():
                    walk(child, level + 1)
                return
            payload = part.get_payload(decode=True) or b""
            if filename or part.get_content_disposition() == "attachment":
                result["attachments"].append({"name": filename, "content_type": kind,
                    "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
                return
            if kind in ("text/plain", "text/html"):
                try:
                    text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                except LookupError:
                    text = payload.decode("utf-8", errors="replace")
                urls.update(u.rstrip(".,;!?)\u005d}") for u in URL_RE.findall(unescape(text)))
                if kind == "text/html":
                    links = Links()
                    links.feed(text)
                    links.close()
                    links.finish_anchor()
                    urls.update(links.values)
                    result["links"].extend(links.links)
        walk(message, depth)
        result["urls"] = sorted(urls)
        return result

    return enrich(parse(raw, 0, "report"))
