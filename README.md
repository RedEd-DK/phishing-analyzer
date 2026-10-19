# Phishing analyzer MVP

Read-only Microsoft Graph collector for `phishing@rededucation.com`.
Uses OAuth client credentials, polls Inbox, extracts original attached emails,
and stores raw MIME plus structured evidence and offline security findings in SQLite. No OpenAI/GPT, Jira,
mailbox writes, automated replies, sender blocking, or URL fetching.
Python standard library only; Docker runs Python 3.12 as an unprivileged user.

## Start with Docker

Install/start Docker Desktop, then:

```sh
cd /Users/dhanush/Desktop/Python/phishing-analyzer
cp .env.example .env
chmod 600 .env
```

Edit `.env` locally and set `CLIENT_SECRET` to a current Entra client secret
**value**, not its secret ID. The tenant and client IDs are prefilled. No secret
is supplied in this project. If an earlier secret was exposed, revoke it and use
a replacement. For Compose `.env` values containing `$` or `#`, use single quotes
around the complete secret value to prevent interpolation or comment parsing.

```sh
docker compose build
docker compose run --rm analyzer python -m app.main --once
docker compose up -d
docker compose logs -f analyzer
```

One-shot polling returns 0 for success, 1 for processing/network failure, and 2
for invalid configuration. An empty Inbox is a successful poll. Logs show counts
and exception types; subjects, bodies, URLs, tokens, and secrets are not logged.
Do not print `docker compose config` with real credentials: it resolves secrets.

Stop with `docker compose down`. The named `analyzer-data` volume persists across
restarts/rebuilds. `docker compose down -v` deletes stored evidence and processing
history; the next start will process Inbox messages again.

## Entra / Exchange authorization

Use the existing app registration and Exchange Online application RBAC scope
for this mailbox. Reading MIME content needs effective application `Mail.Read`
access (`Application Mail.Read` when assigned through Exchange RBAC).
Do not grant Mail.Send or Mail.ReadWrite for this collector. Broad Entra
application permissions and Exchange RBAC grants can be additive: verify that
the app is authorized only for the intended mailbox, including an out-of-scope
mailbox authorization test. The app itself does not alter permissions.

The token POST uses the tenant-specific OAuth v2 endpoint, client credentials,
and `https://graph.microsoft.com/.default`. Every Graph request is GET.
Messages are requested with immutable IDs; bearer tokens are restricted to
Graph URLs under the configured mailbox path and redirects are disabled.

## Processing and evidence

Every poll traverses **all pages of the current Inbox**, including existing
messages on first run. Read status is irrelevant. Other folders are excluded;
messages moved out of Inbox before polling can be missed. The app does not mark
anything read or move/delete it. Full rescans favor simplicity and recovery over
large-mailbox efficiency; delta queries/webhooks are future work.

SQLite keys records by mailbox and immutable Graph message ID. A transaction
saves raw MIME, parsed JSON, and the deduplication marker together. Completed
records are skipped across restarts. Failed messages remain eligible for the
next poll while other messages continue. A separately delivered copy is a
separate report, even if its Internet Message-ID matches. Use one worker per
volume; this is not a distributed queue.

The parser distinguishes the reporting wrapper from attached originals:

- Handles `message/rfc822` and `.eml` files (including base64 attachments),
  multiple attached originals, and nested forwards.
- Records all headers, preserving repeated `Received` fields, plus subject,
  sender, SHA-256, attachment metadata, and HTTP/HTTPS URLs.
- Finds plaintext URLs and HTML link/resource/form targets; originals have
  separate header and URL evidence in the `originals` list.
- Keeps full fetched MIME in the database, so evidence is retained even though
  decoded attachment files are never written to disk using untrusted filenames.

Ordinary inline forwards cannot recover authentic original headers; their text
is analyzed as the wrapper body. Outlook `.msg`, TNEF/winmail.dat, encrypted
messages, archives, defanged URLs, and attachment document contents are not
decoded. Send the suspect email as an `.eml` attachment for original headers.
Recorded Authentication-Results/SPF/DKIM/DMARC headers are untrusted evidence;
this MVP does not independently verify them or assign a phishing verdict.
MIME supplied by Graph may be normalized, rather than the original SMTP bytes.

The default message cap is 25 MiB; oversized responses fail without being marked
complete. MIME traversal is limited to depth 8 and 1,000 parts. Malformed or
unsupported messages may require manual review. The worker retries network
errors, 429 and selected 5xx errors with bounded backoff; it honors Retry-After
and refreshes a rejected token once. Permanent failures retry on later polls.

## Security findings and review commands

After updating sources, rebuild and restart the collector:

```sh
docker compose up -d --build
```

New reports now include an `assessment` on the reporting email and separately
on every attached original. Refresh existing saved messages from their retained
MIME without fetching mail again:

```sh
docker compose exec -T analyzer python -m app.reports --reanalyze --limit 1
```

Show the latest five reports as readable investigation reports:

```sh
docker compose exec -T analyzer python -m app.reports --limit 5
```

Default output is readable text, with reporting time, sender/Reply-To, findings,
evidence, extracted URLs, attachments, authentication limitations, and suggested
investigator checks. The reporting email and each attached original have separate
sections. A message's Date header is shown as unverified and is distinct from
the reporting mailbox's Graph receive time (UTC).

Export a standalone HTML report into the persistent Docker volume:

```sh
docker compose exec -T analyzer python -m app.reports --limit 5 --format html --output /data/investigation-reports.html
docker compose cp analyzer:/data/investigation-reports.html ./investigation-reports.html
```

Open the copied HTML file in a browser. It needs no network connection or
external assets. Supporting evidence and complete headers are expandable. Links
are shown as defanged text (for example `hxxps://example[.]com`) and do not become
clickable links. Email markup is escaped; terminal controls and text direction
controls are shown as escapes. This formatting does not modify retained evidence.
The HTML is generated on demand; rerun the export to include newly processed mail.

Use `--output /data/investigation-reports.txt` to save readable text instead.
Use `--json` (or `--format json`) for a JSON array containing the selected reports'
full extracted evidence; previous releases printed separate JSON objects.
`--json` and `--format` are mutually exclusive. `--limit` accepts 1–1000 records.
Output files are written atomically with private file permissions; on failure,
an existing export is preserved. Exports may contain sensitive email information
even though URLs are defanged; do not commit or share them outside your process.

These commands print email evidence; keep output private. Inspection
opens SQLite read-only. Explicit `--reanalyze` updates parsed JSON only, keeps
raw MIME and original processing timestamps intact, and reports failed refreshes
without discarding their existing records. No client secret is needed by this
utility itself; it makes no Graph or external requests.

Each finding has a stable `code`, `priority`, explanation (`detail`), and
supporting `evidence`. `assessment.version` is 1. `review_priority` covers only
that message; `overall_review_priority` is the highest priority across the
message and all attached originals. Priorities are informational, low, medium,
and high. They guide human review; they are not probabilities or phishing verdicts.
`verdict` remains `not_determined`, including when there are no warning indicators.

Checks include:

- Missing/ambiguous sender; exact From/Reply-To domain differences (medium).
  Return-Path differences are informational because delivery services often use them.
- Reported SPF/DKIM/DMARC failures/errors from Authentication-Results headers
  (informational). All such headers, including apparent passes, remain unverified.
- Different displayed URL and HTML target hostnames (medium), IP address links
  or embedded user-info (medium), HTTP and internationalized domains (low).
- Executable/script/shortcut extensions and double executable extensions (high),
  macro-capable/active content extensions (medium), archives (low), and filename
  direction controls (high). This classifies filenames; it does not inspect content.
- MIME parser defects (low).

These heuristics can flag legitimate mail and miss harmful mail. Comparisons use
exact normalized domains/hostnames, not registrable domains or a public suffix
list. For example, subdomains can trigger a mismatch. Tracking links can also
trigger a displayed-target mismatch. The HTML check requires visible text that
is itself a complete HTTP(S) URL; friendly labels such as "Click here" do not
establish a domain claim. This MVP does not unwrap Safe Links, follow redirects,
verify signatures, resolve DNS, check reputation, execute files, or scan archives.
Authentication-Results trust is intentionally not inferred from its authserv-id;
see [RFC 8601's trust model](https://www.rfc-editor.org/rfc/rfc8601.html).

For the provided safe `.eml`, expect medium review priority from
`reply_to_domain_mismatch` and `link_display_target_mismatch`, with
`reported_authentication_failure` as informational evidence. Its fabricated
failure headers and reserved example domains are training data, not evidence
of an actual phishing incident.

## Read saved results

The database is `/data/reports.sqlite3` inside the container. To inspect parsed
evidence explicitly (this prints potentially sensitive email content):

```sh
docker compose exec -T analyzer python - <<'PY'
import json, sqlite3
db = sqlite3.connect('file:/data/reports.sqlite3?mode=ro', uri=True)
for mid, received, report in db.execute(
    'SELECT message_id, received_at, report_json FROM reports ORDER BY processed_at DESC LIMIT 5'
):
    print(json.dumps({'id': mid, 'received': received, 'report': json.loads(report)}, indent=2))
PY
```

`raw_mime` stores the fetched report bytes. `report_json` stores the report with
its recursively extracted `originals`; `received_at` is Graph's receive time,
and `processed_at` is SQLite's UTC processing time. Evidence contains private
email data: restrict access to the Docker volume and set your own retention and
backup policy. There is no automatic evidence deletion. Compose injects the
secret at runtime; it is visible to people with Docker administrator access.
Neither `.env` nor evidence enters the Docker build context.

## Configuration

| Variable | Default / requirement |
| --- | --- |
| `TENANT_ID` | `9070ef23-9a31-45a8-9b14-45111a4ebbbe` |
| `CLIENT_ID` | `3e16daef-f2ac-4761-86eb-2d80e04d9a7a` |
| `CLIENT_SECRET` | Required locally; never committed |
| `MAILBOX` | `phishing@rededucation.com` |
| `POLL_SECONDS` | `60` (minimum `5`) |
| `MAX_MESSAGE_BYTES` | `26214400` |
| `DATA_DIR` | `/data` in Docker, `data` outside Docker |

## Offline tests and local development

Python 3.9+ can run the project without installing packages:

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q app tests
```

Tests mock Microsoft responses and do not read a real mailbox. They cover
forwarded originals, HTML/plaintext URLs, repeated headers, nesting limits,
persistent idempotency, failure recovery, paging, token refresh, throttling,
size limits, and rejecting unexpected pagination destinations. Report tests also
cover normal mail, legitimate Reply-To differences, misleading HTML links, inert
test attachments with executable filenames, nested original separation, escaped
email HTML, terminal controls, private exports, and preserving stored evidence.

For a local live run, export configuration in your shell first, including a
secret entered without echo; then run `python3 -m app.main --once`. Local Python
does not automatically load `.env`; Docker Compose does. Do not source untrusted
configuration as shell code.

For troubleshooting, 401 usually points to credentials/expiry; 403 to effective
mailbox authorization. Check Microsoft Entra sign-in and Exchange authorization
diagnostics without printing token responses or secrets. Live authentication
requires credentials and has not been assumed merely because offline tests pass.

## Microsoft references

- [Client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [List messages and pagination](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0)
- [Get MIME and attached original emails](https://learn.microsoft.com/en-us/graph/outlook-get-mime-message)
- [Immutable message IDs](https://learn.microsoft.com/en-us/graph/outlook-immutable-id)
