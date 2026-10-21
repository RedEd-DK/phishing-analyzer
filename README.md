# Phishing analyzer

Microsoft Graph analysis and response service for `phishing@rededucation.com`.
Uses OAuth client credentials, polls Inbox, extracts original attached emails,
and stores raw MIME, extracted body text, structured evidence and security findings in SQLite.
Optional OpenAI API analysis adds contextual classification alongside offline checks.
It can automatically send a styled HTML analysis response with a plain-text fallback to the reporting sender,
with escalation guidance to `security@rededucation.com`. No Jira,
message deletion/moving, sender blocking, or URL fetching.
Python standard library only; Docker runs Python 3.12 as an unprivileged user.

## Intended workflow: receive, analyze, reply

1. An employee reports an email to `phishing@rededucation.com`, preferably with
   the original attached as `.eml`.
2. The collector saves the report, extracts originals, and performs offline checks.
3. In `send` mode, it responds from `phishing@rededucation.com` to the outer
   reporting sender. It does not use the suspect original's sender or the outer
   Reply-To, and it does not reply-all or copy Security.
4. The response includes a prominent assessment result, findings, defanged links, attachment
   indicators, limits of the assessment, and this instruction:
   "If you need to escalate this further, forward this email thread and the original reported email to security@rededucation.com."

If attached originals exist, response findings focus on those originals so that
an employee's signature links are not treated as the suspect message's findings.
Without an extracted original, the response explains that its analysis covers
only the submitted email and asks for `.eml` for fuller analysis. It never certifies
an email safe. Replies contain both HTML and plain-text alternatives and no original attachments,
tracking pixels, or raw email body quotes. A valid outer Message-ID is used for
In-Reply-To/References threading; mailbox client grouping can vary.

### Response design

Responses use a Red Education-inspired black, charcoal and red design with a clear coverage notice, review priority,
message details, findings, grouped destination domains, attachment names and a
Security escalation section. When no original `.eml` was extracted, the main
status says **Original email needed**; an informational priority never implies
that the email is safe.

The brand treatment follows [Red Education's website](https://www.rededucation.com/):
the signature `#e41f1b` red, black/white contrast, a clear Red Education wordmark,
and bold condensed headings. Installed font fallbacks approximate the website's
Bebas Neue/Roboto hierarchy without fetching fonts remotely. Brand red is used
for the company accent and contact action; review priorities keep separate semantic
colours so the company branding does not imply a high-risk verdict.

Long tracking URLs are grouped by destination hostname. Query values and long
paths are shortened in both HTML and text, with the complete URLs retained in
saved investigation evidence. This is presentation only: no redirect resolution,
reputation lookup, authentication validation or extra scanning is performed.

The HTML uses presentation tables, inline styles and system fonts. It includes
no remote images, fonts, scripts or tracking pixels. Suspect links remain defanged
text. The only generated clickable link is **Contact Security**, a `mailto:` link
to the configured escalation address. It opens a new email; the response explains
that the reporter should forward the thread and attach the original for context.
It does not send or escalate anything on click.

HTML rendering varies by email client; the plain-text alternative carries the
same scope, findings and next steps. Detailed output is bounded to six original
messages, five findings, four destination groups and four attachment names per
message, with a pointer to retained evidence when more details exist. New queued
responses use the new template; already queued MIME and accepted replies are not
rewritten or resent. Response recipient rules and delivery safeguards are unchanged.

### Modes and activation

The template defaults to `AUTO_REPLY_MODE=preview`: eligible responses are saved
in the local outbox without sending. `off` disables queueing and dispatch;
`send` activates delivery and requires effective Mail.Send authorization.

Set these locally in `.env` after establishing the scoped sending permission:

```dotenv
AUTO_REPLY_MODE=send
ESCALATION_EMAIL=security@rededucation.com
REPORTER_DOMAINS=rededucation.com
REPLIES_PER_HOUR=10
```

Then apply configuration with `docker compose up -d --build` (a restart alone
does not apply changed environment variables). Reports received before the first
non-off startup's persistent activation timestamp are analyzed but skipped for
automatic replies. Rebuilding/restarting keeps that timestamp. This prevents
historical Inbox backfill from producing a burst of unsolicited replies.
Preview-mode pending responses received after activation become eligible when
send mode is enabled. Skipped historical messages are not retroactively queued.

Only reporting senders on exact `REPORTER_DOMAINS` domains receive replies by
default. External reports are still analyzed and stored. Expand this comma-separated
allowlist only if the reporting workflow requires it. A From-domain allowlist is
not authentication and cannot prove the reporter's identity.

### Loop prevention and delivery state

Incoming automatic replies, analyzer-marked responses, bulk/list messages,
bounces, service/security senders and common no-reply senders are skipped.
Outgoing responses carry Auto-Submitted: auto-replied, X-Auto-Response-Suppress:
All, and an analyzer marker. A per-recipient hourly limit delays additional
responses; at most 20 ready responses are attempted per poll. The collector does
not automatically forward mail to Security.

The SQLite outbox is keyed by mailbox and immutable received-message ID.
Claims persist before the send POST. Accepted responses are not resent on later
polls or restarts. One worker owns the evidence volume through a process lock
(local execution supports macOS/Linux; use Docker on Windows).

Delivery states are:

| State | Meaning |
| --- | --- |
| pending | Response prepared; preview mode or waiting to send |
| accepted | Graph returned 202; final delivery is not confirmed |
| retry | Rejected before submission or throttled; retries after the delay |
| blocked | 401/403; check credentials and effective Mail.Send authorization; retry after 5 minutes |
| skipped | Historical mail, ineligible sender or loop-prevention rule |
| uncertain | Network/5xx/unexpected outcome or interrupted send; never auto-retried |
| failed | Permanent 4xx/local rejection; manual review required |

Graph mail sending has no application idempotency key. A timeout or process crash
can leave delivery unknown. The collector favors avoiding duplicate replies:
review Sent Items and Exchange message tracing before manually reconciling an
uncertain job. Do not reset uncertain jobs blindly. Exactly-once delivery is not
claimed. Received message evidence remains intact even if response sending fails.

Inspect states and exact stored reply text without sending anything:

```sh
docker compose exec -T analyzer python -m app.replies --status
docker compose exec -T analyzer python -m app.replies --limit 5
docker compose logs --tail=20 analyzer
```

The outbox contains recipient addresses and response text; treat the evidence
volume, exports and backups as private. Processing logs contain only counts,
states and fixed error reasons, not email contents or credentials.

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
Preview/off mode needs only read access. Send mode additionally needs effective
application `Mail.Send` (`Application Mail.Send` with Exchange RBAC), restricted
to the same phishing mailbox. Mail.ReadWrite is not required. Broad Entra
application permissions and Exchange RBAC grants can be additive: verify that
the app is authorized only for the intended mailbox, including an out-of-scope
mailbox authorization test. The app itself does not alter permissions.

The token POST uses the tenant-specific OAuth v2 endpoint, client credentials,
and `https://graph.microsoft.com/.default`. Mailbox reading uses GET; sending
uses a single-attempt MIME POST to `/users/{mailbox}/sendMail`.
Messages are requested with immutable IDs; bearer tokens are restricted to
Graph URLs under the configured mailbox path and redirects are disabled.

An Exchange administrator can reuse the existing validated management scope:

```powershell
Connect-ExchangeOnline
New-ManagementRoleAssignment -Name "PhishingAnalyzer-MailSend" `
  -App "3e16daef-f2ac-4761-86eb-2d80e04d9a7a" `
  -Role "Application Mail.Send" `
  -CustomResourceScope "YOUR_EXISTING_PHISHING_ONLY_SCOPE"
Test-ServicePrincipalAuthorization `
  -Identity "3e16daef-f2ac-4761-86eb-2d80e04d9a7a" `
  -Resource "phishing@rededucation.com" |
  Format-Table RoleName,GrantedPermissions,AllowedResourceScope,InScope
```

Replace the scope placeholder with the existing verified scope name; do not
create an unrestricted assignment. Also test an approved out-of-scope mailbox:
Mail.Send must be out of scope there. RBAC tests exclude separate Entra grants,
so review broad permissions too. Changes can take time to become effective.
See [Exchange application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
and [Graph sendMail permissions and 202 semantics](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0).

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
the offline layer does not independently verify them or assign a phishing verdict.
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
establish a domain claim. The offline layer does not unwrap Safe Links, follow redirects,
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
| `AUTO_REPLY_MODE` | `preview`; `send` or `off` also accepted |
| `ESCALATION_EMAIL` | `security@rededucation.com` |
| `REPORTER_DOMAINS` | `rededucation.com`; comma-separated exact reporting domains |
| `REPLIES_PER_HOUR` | `10` per reporting recipient; 1–100 |

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

## OpenAI API analysis

Offline checks always run first. With `AI_ANALYSIS_MODE=on`, new reports received
since AI activation also get one bounded OpenAI Responses API request. The
application combines the structured AI assessment with offline findings before
building the existing branded HTML/plain-text reply. The API does not generate
HTML, set recipients, send mail, browse links or execute files.

### Local setup

Add these values to your private `.env` (never paste a key into a chat or commit it):

```dotenv
AI_ANALYSIS_MODE=on
OPENAI_API_KEY='YOUR_OPENAI_API_KEY'
OPENAI_MODEL=gpt-4.1-mini
AI_MAX_INPUT_CHARS=20000
AI_MAX_OUTPUT_TOKENS=1200
AI_DAILY_LIMIT=100
AI_TIMEOUT_SECONDS=25
```

Use an OpenAI API project with API billing and access to the selected model.
The model is configurable. GPT-4.1 mini is the initial non-reasoning baseline;
it has not been evaluated for your organization's actual mail distribution.
A paid ChatGPT subscription alone is not API billing or an API credential.
Keep `.env` permissions at `600`. Rebuild after installing this version; recreate
the service whenever environment values change:

```sh
docker compose up -d --build analyzer
docker compose exec -T analyzer python -m app.ai_check
```

An optional connection test makes **one billable API request with synthetic
training text only**. It does not read the mailbox, send a reply, or alter reports:

```sh
docker compose exec -T analyzer python -m app.ai_check --test
```

The synthetic test is a manual diagnostic outside the collector's daily limit.
Expect `status: completed` and normally `classification: likely_phishing`.
A different classification is a reason to evaluate the model and prompt further,
not proof of correct detection. A missing/invalid key, API outage, refusal,
invalid structured answer or exhausted limit produces a visible offline fallback.
Set `AI_ANALYSIS_MODE=off` and recreate to disable future API requests.

### Two-result determination policy v4

Every analysis reply has exactly one of two main results:

- **SAFE**, in green: AI finds legitimate context at medium/high confidence,
  material original-email evidence is available, and there are no material warnings.
- **SUSPICIOUS**, in red: strong/combined warning evidence, phishing/spam context,
  unresolved sensitive actions, missing essential content, low confidence, or an API
  failure requires review. The reason distinguishes a detected warning from an
  inability to clear a message. Suspicious does not automatically mean malicious.

The retired Unable to determine result is no longer displayed. Genuine uncertainty
maps to Suspicious with a clear review explanation, never Safe by default. Internal
AI classifications still retain uncertainty for audit and policy decisions.

The Jira regression revealed that a 320-character Authentication-Results header
was shortened to 300 characters and incorrectly marked the entire message incomplete,
although both the plaintext and HTML message content were present. Coverage now
separates **material gaps** from **shortened unverified metadata**:

- Missing/truncated body, omitted original, navigation links, attachment metadata,
  findings or sender identity details are material gaps and prevent Safe.
- Shortened Authentication-Results/date metadata is recorded in `metadata_notes`
  but does not make an otherwise complete message incomplete. The full header
  and its locally extracted authentication findings remain in saved evidence.
- Sender identity headers are prioritized over repeated diagnostic headers; a long
  diagnostic-header list cannot crowd From/Reply-To/Return-Path out of the request.
- `coverage_gaps` records actual omissions and the messages affected. A real input
  budget reduction remains material. Diagnostic explanations are themselves bounded.

Weighted risk families remain in place. Policy points are not probabilities:
dangerous executables/obfuscated files 8; active content or URL user-info deception
5; misleading displayed link 3; IP-based navigation 2; Reply-To domain difference
or an unverified authentication failure 1; HTTP/internationalized domain .5.
A score of 5 or a strong warning requires Suspicious. Repeated correlated findings
count once per family per original. Safe requires at most 1.5 points and no
material blockers or sensitive action. Internal names, known brands and HTTPS
are not unconditional allowlists. Credential/MFA requests and embedded instructions
to manipulate the analyzer remain warnings even with benign AI prose.

Both plaintext and differing HTML alternatives are considered. Resource-only images
are summarized separately from navigational links. Missing authentication alone,
ordinary signature images and benign routine deadlines are not threats by themselves.
Safe remains an assessment of available evidence, not verified sender authenticity,
a malware scan or a guarantee about an unvisited destination.

Saved decisions include policy version, basis, weighted signals and blockers. Old
reports/replies are not automatically reassessed or resent. Offline reanalysis
preserves the historical AI coverage result; submit a new report for a fresh API
analysis with the corrected coverage metadata.

The multi-signal approach is informed by
[Microsoft's anti-spoofing evaluation](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-spoofing-about),
[SpamAssassin's weighted tests](https://spamassassin.apache.org/full/4.0.x/doc/Mail_SpamAssassin_Conf.html),
and [Cloudflare's content, URL and sender analysis](https://developers.cloudflare.com/cloudflare-one/email-security/reference/how-es-detects-phish/).
Weights are application-specific initial heuristics, not their proprietary models
or statistically calibrated scores. No reputation feed, live URL browsing or
attachment sandbox was added. Real-mail precision/recall requires labelled evaluation.

### Data sent and retained

Each request contains up to six original/nested messages (or the submitted copy
when no original is attached): bounded subject/body text, selected unverified
From/Reply-To/Return-Path/authentication/date headers, up to 20 non-resource URLs, 10 displayed
links, summarized image/resource hostnames, 10 attachment metadata entries and
20 material offline findings per message. Embedded resources are classified by
HTML role, not a trusted-domain allowlist. All original URLs and findings remain
in local evidence. Pure-resource HTTP warnings do not inflate the decision score. The
serialized evidence is capped at `AI_MAX_INPUT_CHARS`; instructions and the output
schema add overhead. This is a character bound, not an exact token bound.

Attachment binaries, raw MIME, Received routing headers, Message-IDs, reporter
wrapper/signature when originals exist, and local credentials are excluded.
Email address local parts are masked; URL credentials, query strings and fragments
are removed. This reduces disclosure but is **not complete anonymization**:
names, body content and URL paths may still contain sensitive information. URL
redaction also limits analysis of redirect/payment links. Incomplete coverage is
recorded and cannot produce a Safe result.

The fixed endpoint is `https://api.openai.com/v1/responses`, with TLS and redirects
disabled. No tools or conversation history are provided. Email data stays in the
user-input portion; a separate instruction defines it as untrusted evidence.
Structured outputs are validated locally; model text is escaped/defanged before
rendering. These measures reduce prompt-injection risk but cannot guarantee model
accuracy or immunity to adversarial content.

Requests set `store=false`, disabling Responses application-state storage. This
is **not a promise of zero retention**: default abuse-monitoring logs may retain
content for up to 30 days, subject to OpenAI's data controls and exceptions. API
content is not used for model training by default unless you opt in. Review your
organization's data policy before forwarding sensitive reports through the API.
See [OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data).

Local evidence retains body text and AI results. `report.ai_analysis` records
status, model, prompt version, coverage, structured answer and actual token usage;
`report.combined_assessment` records the resulting decision. Treat all reports,
exports and backups as private. The existing `.env` and data exclusions apply.

### Attempts, costs and failures

A durable `ai_jobs` reservation precedes each automatic request. The worker lock
allows one collector per volume. A report gets at most one automatic API attempt;
network errors, 429, 5xx and interrupted/unknown outcomes are not blindly retried.
Outcomes persist before a reply is queued. Restarting or rescanning does not
repeat a paid request. Existing outbox jobs are not regenerated or resent.

The default limit is 100 automatic attempts per UTC day across the evidence
volume, including failed or uncertain attempts. This is not a dollar spending
cap. `max_output_tokens` caps generated output; actual input/output token counts
are recorded on received API responses, including incomplete outputs when
available. Unknown network outcomes may still incur charges not reflected in
local counts. Manual diagnostics are additional calls. Configure API project
budgets/alerts as an additional control.

When a key is absent or a limit is reached, the report receives an offline
fallback. It is not automatically reassessed tomorrow or when credentials change.
Previously processed backlog is not uploaded; send a new report for fresh
analysis. Offline `app.reports --reanalyze` refreshes local findings and body text
while retaining the recorded AI outcome; it makes no API request and does not
resend replies.

Inspect recent reports and counts without displaying credentials:

```sh
docker compose exec -T analyzer python -m app.ai_check
docker compose exec -T analyzer python -m app.reports --limit 3
docker compose logs --tail=20 analyzer
```

Use `app.reports --json` for complete AI usage/coverage fields. Report inspection
prints potentially private evidence. Runtime logs include only fixed status and
token counts. No live model-quality claim follows from mocked tests.

API implementation references:
[Structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs),
[GPT-4.1 mini](https://developers.openai.com/api/docs/models/gpt-4.1-mini),
[data controls](https://developers.openai.com/api/docs/guides/your-data).

### Repeatable synthetic evaluation

Offline tests include routine business messages and adversarial variants:

```sh
python3 -m unittest discover -s tests -q
```

For a small live acceptance set with the configured model:

```sh
docker compose exec -T analyzer python -m app.evaluate --live
```

This makes **eight billable API requests** using synthetic examples only. No
mailbox reads, report updates, reply sending, or automatic retries occur. These
manual calls are outside the collector's daily cap. Expected cases: survey,
meeting, paid receipt and Jira notice Safe; password/MFA request, executable
attachment, prompt injection and missing body Suspicious. Exit code 1 means
a mismatch or API failure. This is not a statistically representative benchmark.
The earlier policy-v3 seven-case run matched 7/7; that historical set used a third
result for missing content. The current binary set includes the Jira-header regression.
Broader precision/recall estimates require a separately labelled real-mail corpus.

The current policy-v4 live acceptance run matched 8/8 synthetic cases with 8,753
total tokens, including the long-header Jira case as Safe. This remains a small
acceptance set, not a real-mail detection accuracy estimate.
