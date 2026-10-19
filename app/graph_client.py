"""OAuth client credentials; Graph operations are GET only."""
import json
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

GRAPH = "https://graph.microsoft.com/v1.0"


class GraphError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GraphClient:
    def __init__(self, config, opener=None, sleep=time.sleep):
        self.config = config
        self.opener = opener or build_opener(NoRedirect())
        self.sleep = sleep
        self.token = None
        self.expires = 0
        self.retry_after = 0
        self.base = GRAPH + "/users/" + quote(config.mailbox, safe="")

    def _request(self, request, limit):
        if time.monotonic() < self.retry_after:
            raise GraphError("Waiting for Microsoft's retry window")
        for attempt in range(4):
            try:
                with self.opener.open(request, timeout=30) as response:
                    data = response.read(limit + 1)
                    if len(data) > limit:
                        raise GraphError("Response exceeded configured size limit")
                    return data
            except HTTPError as exc:
                status = exc.code
                retry = exc.headers.get("Retry-After", "") if exc.headers else ""
                exc.close()
                if status not in (429, 500, 502, 503, 504) or attempt == 3:
                    # Do not expose response bodies, credentials, tokens, or URLs in errors.
                    raise GraphError("Microsoft HTTP status %s" % status) from None
                try:
                    delay = float(retry)
                except ValueError:
                    try:
                        delay = (parsedate_to_datetime(retry) - datetime.now(timezone.utc)).total_seconds()
                    except (ValueError, TypeError, OverflowError):
                        delay = 2 ** attempt
                # Long Retry-After values defer to the next poll instead of retrying early.
                if delay > 60:
                    self.retry_after = time.monotonic() + delay
                    raise GraphError("Microsoft requested a longer retry delay") from None
                self.sleep(max(0, delay))
            except (URLError, TimeoutError, OSError):
                if attempt == 3:
                    raise GraphError("Microsoft network request failed") from None
                self.sleep(2 ** attempt)

    def _access_token(self):
        if self.token and time.monotonic() < self.expires:
            return self.token
        payload = urlencode({"client_id": self.config.client_id,
                             "client_secret": self.config.client_secret,
                             "scope": "https://graph.microsoft.com/.default",
                             "grant_type": "client_credentials"}).encode()
        req = Request("https://login.microsoftonline.com/" + self.config.tenant_id +
                      "/oauth2/v2.0/token", data=payload,
                      headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        try:
            result = json.loads(self._request(req, 1024 * 1024))
            self.token = result["access_token"]
            self.expires = time.monotonic() + max(0, int(result["expires_in"]) - 60)
        except (ValueError, KeyError, TypeError):
            raise GraphError("Invalid Microsoft token response") from None
        return self.token

    def get(self, url, raw=False):
        # Only Graph pagination links within this mailbox may receive the bearer token.
        parsed = urlsplit(url)
        allowed = urlsplit(self.base)
        if (parsed.scheme, parsed.netloc) != (allowed.scheme, allowed.netloc) or not parsed.path.startswith(allowed.path + "/"):
            raise GraphError("Rejected unexpected Graph URL")
        for attempt in range(2):
            req = Request(url, headers={"Authorization": "Bearer " + self._access_token(),
                          "Prefer": 'IdType="ImmutableId"',
                          "Accept": "application/octet-stream" if raw else "application/json"}, method="GET")
            try:
                data = self._request(req, self.config.max_message_bytes if raw else 8 * 1024 * 1024)
                return data if raw else json.loads(data)
            except GraphError as exc:
                if str(exc) != "Microsoft HTTP status 401" or attempt:
                    raise
                self.token = None
                self.expires = 0

    def messages(self):
        url = self.base + "/mailFolders/inbox/messages?" + urlencode({
            "$select": "id,receivedDateTime", "$top": 100})
        visited = set()
        while url:
            if url in visited:
                raise GraphError("Repeated Graph pagination link")
            visited.add(url)
            page = self.get(url)
            yield from page["value"]
            url = page.get("@odata.nextLink")

    def mime(self, message_id):
        return self.get(self.base + "/messages/" + quote(message_id, safe="") + "/$value", raw=True)
