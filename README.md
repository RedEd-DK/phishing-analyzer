# Red Education Phishing Analyzer — VM operations

This service runs on the **`connect` virtual machine**, independently of the laptop.
It polls `phishing@rededucation.com`, extracts attached original emails, runs offline
checks and OpenAI analysis, and replies to eligible internal reporters.
Replies show **SAFE in green** or **SUSPICIOUS in red**, with reasons and guidance to
escalate to `security@rededucation.com`.

## 1. Connect and check the service

From your laptop or another computer that can reach `connect`:

```sh
ssh dhanush.kumar@connect
```

Then run **on the VM**:

```sh
cd /home/dhanush.kumar/phishing
docker compose ps -a
docker compose logs --tail=30 analyzer
```

Look for a running container and a recent `Poll complete: processed=... failed=0`.
`processed=0` means no unprocessed messages were found; it is a successful poll.
A running process alone does not prove Microsoft/OpenAI connectivity.

| Deployment item | Value |
| --- | --- |
| VM SSH target | `dhanush.kumar@connect` |
| VM application directory | `/home/dhanush.kumar/phishing` |
| Git repository / branch | `https://github.com/RedEd-DK/phishing-analyzer.git` / `main` |
| Compose project / service | `phishing-analyzer` / `analyzer` |
| Container / image | `phishing-analyzer-analyzer-1` / `phishing-analyzer-analyzer:latest` |
| Persistent Docker volume | `phishing-analyzer_analyzer-data` |
| Database inside container | `/data/reports.sqlite3` |
| Private VM configuration | `/home/dhanush.kumar/phishing/.env` |
| Current production model | `gpt-6.1-sol` (selected in private `.env`) |
| Current production modes | `AUTO_REPLY_MODE=send`, `AI_ANALYSIS_MODE=on` |
| Restart policy | `unless-stopped`; Docker is enabled at VM boot |

**Run only one production worker.** The old Mac worker is stopped. Keep it stopped
while the VM is processing mail. A file lock prevents two workers on one volume;
it does not protect two hosts with separate database copies.

There is no web dashboard, HTTP listener, public port or website URL for this
service. It needs outbound HTTPS to Microsoft login/Graph and `api.openai.com`,
working DNS, and access to the container registry/GitHub when building/updating.
Closing SSH or powering off the laptop does not stop the VM container.

## 2. Everyday commands

All commands below run **on the VM**, from `/home/dhanush.kumar/phishing`.
The private `.env` contains `COMPOSE_PROJECT_NAME=phishing-analyzer`; keep it set
so commands reuse the same container and evidence volume.

| Task | Command |
| --- | --- |
| Start/resume in the background | `docker compose up -d --no-build analyzer` |
| Stop the analyzer, keep its data | `docker compose stop analyzer` |
| Restart the current service | `docker compose restart analyzer` |
| Show running/stopped status | `docker compose ps -a` |
| Show the last 100 log lines | `docker compose logs --tail=100 analyzer` |
| Follow live logs | `docker compose logs -f --tail=50 analyzer` |
| Logs from the last 30 minutes | `docker compose logs --since=30m --timestamps analyzer` |
| Check AI mode/model/key presence | `docker compose exec -T analyzer python -m app.ai_check` |
| Inspect reply status | `docker compose exec -T analyzer python -m app.replies --status` |
| Inspect the latest five saved reports | `docker compose exec -T analyzer python -m app.reports --limit 5` |
| Show the checked-out release | `git log -1 --oneline` |
| Show working-tree changes | `git status --short` |
| Check container resource use | `docker stats --no-stream phishing-analyzer-analyzer-1` |

Press **Ctrl+C** to leave `logs -f`; the background analyzer keeps running.
Report/outbox commands may display private message content or reporter addresses.
`app.ai_check` shows whether a key is configured, not the key itself.

### Restart versus apply changes

- **Temporary issue, unchanged code/configuration:** use `docker compose restart analyzer`.
- **Changed `.env`:** recreate the container; `restart` does not load new values.
- **Changed application code:** rebuild the image and recreate the container.
- **Documentation-only Git update:** pull the files; no rebuild/restart is required.

For configuration changes:

```sh
cd /home/dhanush.kumar/phishing
nano .env
chmod 600 .env
docker compose up -d --no-build --force-recreate analyzer
docker compose exec -T analyzer python -m app.ai_check
docker compose logs --tail=30 analyzer
```

Do not print `cat .env`, `docker compose config`, `printenv`, or full container
inspection output into logs/chats: those can reveal credentials.

## 3. VM power, Docker startup and reboot

### Power on a powered-off VM

The guest is hosted on **VMware**. Open the VMware management console/hosting
portal used by your infrastructure team, select the VM that hosts `connect`, and
choose **Power On**. Wait for Ubuntu and networking, then SSH in and run section 1.
The management-console address and VM inventory name are not stored in this repo.
There is no command inside a powered-off Ubuntu guest that can power it on;
`docker compose up` starts an application container, not a powered-off VM.

### Check/start Docker on an already running VM

Docker is already installed and enabled on this VM. These checks do not restart it:

```sh
systemctl is-active docker
systemctl is-enabled docker
docker --version
docker compose version
```

If Docker is stopped, an authorized VM administrator can start it and enable boot
startup, then start the analyzer:

```sh
sudo systemctl start docker
sudo systemctl enable docker
cd /home/dhanush.kumar/phishing
docker compose up -d --no-build analyzer
```

Use the analyzer's Compose restart for routine issues. Restarting the Docker
daemon affects other containers on this shared VM.

### Restart the entire VM — planned infrastructure maintenance only

This interrupts **all services on the VM** and disconnects SSH:

```sh
sudo reboot
```

Reconnect after the VM is reachable, then verify:

```sh
ssh dhanush.kumar@connect
cd /home/dhanush.kumar/phishing
docker compose ps -a
docker compose logs --tail=30 analyzer
```

The service is configured to resume after a normal host reboot if it was running
beforehand. With `unless-stopped`, a **manually stopped** container remains stopped
across reboot; resume it with `docker compose up -d --no-build analyzer`.
Do not manually stop the container before reboot if you expect automatic resume.
If the container was removed with `docker compose down`, use `up` to recreate it.
See [Docker restart policies](https://docs.docker.com/engine/containers/start-containers-automatically/).

### Power off the entire VM — planned infrastructure maintenance only

```sh
sudo shutdown -h now
```

Analysis stops while the VM is off. Power it on again through VMware, then check
the service. Do not use VM shutdown just to stop this analyzer; use Compose stop.

## 4. Update from GitHub and deploy code

Do this **on the VM**, not on the stopped Mac worker. Take the database/configuration
backups in section 8 before a production code update. First check for local changes;
resolve them intentionally rather than using `git reset --hard` or `git clean`.

```sh
cd /home/dhanush.kumar/phishing
git status --short
git log -1 --oneline
```

When the working tree is clean, save the current image for rollback, pull, build,
run offline tests against the new image, and only then replace the worker:

```sh
cd /home/dhanush.kumar/phishing
PHISHING_PREVIOUS_COMMIT=$(git rev-parse --short HEAD)
docker image tag phishing-analyzer-analyzer:latest "phishing-analyzer-analyzer:rollback-$PHISHING_PREVIOUS_COMMIT" &&
  git pull --ff-only origin main &&
  docker compose build analyzer &&
  docker run --rm --network none --read-only --tmpfs /tmp \
    -v /home/dhanush.kumar/phishing/tests:/app/tests:ro \
    phishing-analyzer-analyzer:latest python -m unittest discover -s tests -q &&
  docker compose up -d --no-build analyzer
```

The `&&` chain stops if pull/build/tests fail. The previous worker continues running
during the build/tests. Do not continue to deployment after a failed check.
Then verify the newly running release and recent polling:

```sh
cd /home/dhanush.kumar/phishing
git log -1 --oneline
docker compose ps -a
docker compose exec -T analyzer python -m app.ai_check
docker compose logs --tail=50 analyzer
```

Polling normally occurs every 60 seconds. Wait for a recent poll result; logs may
initially contain only startup messages. A Graph send acceptance is not delivery
confirmation: for an end-to-end test, submit a new original email and check the reply.

For an already reviewed small update, `docker compose up -d --build analyzer` is
the shorter build/deploy command, but it does not run the offline tests for you.
For a **documentation-only update**, this is sufficient:

```sh
cd /home/dhanush.kumar/phishing
git pull --ff-only origin main
```

Git pulls preserve the ignored private `.env` and Docker volume. Rebuilding or
recreating the service preserves the named volume too. Do not change the Compose
project name, mount an empty replacement volume, or run `docker compose down -v`:
that would lose the history used to avoid duplicate processing/replies.
See [Compose up](https://docs.docker.com/reference/cli/docker/compose/up/) and
[Compose down](https://docs.docker.com/reference/cli/docker/compose/down/).

### Temporary image rollback

Use this only after checking that the previous image is compatible with the current
Compose configuration and database schema. Replace `OLD_COMMIT` with the suffix
of the rollback tag saved above; list available tags first:

```sh
docker image ls phishing-analyzer-analyzer
```

Then:

```sh
cd /home/dhanush.kumar/phishing
docker compose stop analyzer &&
  docker image tag phishing-analyzer-analyzer:rollback-OLD_COMMIT phishing-analyzer-analyzer:latest &&
  docker compose up -d --no-build --force-recreate analyzer
docker compose logs --tail=50 analyzer
```

This changes the running image only; the Git checkout remains at the newer commit.
Record the rollback and reconcile source/configuration before the next build.
Do not restore an older database just to roll back code; it can lose reply history.

## 5. Configuration and credential rotation

Production configuration is already present on the VM. **Do not overwrite `.env`
with `.env.example` on the existing deployment.** Edit only the values that need
changing and recreate the service using section 2.

The production settings include these non-secret values:

```dotenv
COMPOSE_PROJECT_NAME=phishing-analyzer
TENANT_ID=9070ef23-9a31-45a8-9b14-45111a4ebbbe
CLIENT_ID=3e16daef-f2ac-4761-86eb-2d80e04d9a7a
MAILBOX=phishing@rededucation.com
AUTO_REPLY_MODE=send
AI_ANALYSIS_MODE=on
OPENAI_MODEL=gpt-6.1-sol
ESCALATION_EMAIL=security@rededucation.com
REPORTER_DOMAINS=rededucation.com
```

`CLIENT_SECRET` and `OPENAI_API_KEY` belong only in private `.env`/approved secret
storage. Never commit or paste real values. An Entra client secret must be its
**value**, not its secret ID. Quote complete values containing `$` or `#` with
single quotes in Compose `.env`; do not source `.env` as a shell script.

| Variable | Default / allowed values | Production note |
| --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | Compose project name | Keep `phishing-analyzer` to reuse existing state |
| `TENANT_ID`, `CLIENT_ID` | IDs above | Existing Entra application |
| `CLIENT_SECRET` | Required | Private, current Entra secret value |
| `MAILBOX` | `phishing@rededucation.com` | Scoped Microsoft read/send access |
| `POLL_SECONDS` | `60`; minimum `5` | Inbox polling interval |
| `MAX_MESSAGE_BYTES` | `26214400`; minimum `1024` | Maximum fetched MIME size |
| `DATA_DIR` | `/data` in Compose | Do not change the volume mapping |
| `AUTO_REPLY_MODE` | `preview`; `off`, `preview`, `send` | VM uses `send` |
| `ESCALATION_EMAIL` | `security@rededucation.com` | Guidance only; no automatic escalation |
| `REPORTER_DOMAINS` | `rededucation.com`; comma-separated exact domains | Recipients are outer reporting senders only |
| `REPLIES_PER_HOUR` | `10`; range `1–100` | Per reporting recipient |
| `AI_ANALYSIS_MODE` | `off`; `off`, `on` | VM uses `on` |
| `OPENAI_API_KEY` | Empty | Private billed API credential |
| `OPENAI_MODEL` | Code/template default `gpt-4.1-mini` | VM overrides to `gpt-6.1-sol` |
| `AI_MAX_INPUT_CHARS` | `20000`; range `4000–40000` | Evidence character bound, not exact token bound |
| `AI_MAX_OUTPUT_TOKENS` | `1200`; range `300–4000` | Output token ceiling |
| `AI_DAILY_LIMIT` | `100`; range `1–1000` | Automatic attempts per UTC day across volume |
| `AI_TIMEOUT_SECONDS` | `25`; range `5–45` | API request timeout |

### Rotate a Microsoft or OpenAI credential

1. Create the replacement in the appropriate Entra/OpenAI administration portal.
2. Update only `CLIENT_SECRET` or `OPENAI_API_KEY` using `nano .env` on the VM.
3. Keep permissions at `600`; recreate using section 2.
4. Confirm a successful mailbox poll for Microsoft, or use the synthetic AI test
   below for OpenAI. Revoke the old credential after the replacement is verified.

For OpenAI key validation, one **billable synthetic request**, no mailbox access:

```sh
cd /home/dhanush.kumar/phishing
docker compose exec -T analyzer python -m app.ai_check --test
```

This diagnostic works independently of `AI_ANALYSIS_MODE`; a successful test alone
does not enable ongoing AI. `app.ai_check` should also show `mode: on`.
Missing/invalid AI credentials do not mark mail Safe: the service uses offline
checks and explains the need for review under Suspicious.

### Pause automated replies or AI without stopping collection

Edit `.env` to `AUTO_REPLY_MODE=off` to stop new reply queueing and sending, or to
`preview` to prepare eligible responses without sending. Set `AI_ANALYSIS_MODE=off`
to stop future automatic OpenAI requests. Then recreate as in section 2.

Existing pending preview responses can become eligible when `send` is re-enabled.
Review them first; switching modes does not erase them. A failed/capped AI attempt
is not automatically retried after changing a key or waiting until tomorrow.

## 6. Microsoft authorization — administrator checks

The VM reuses the existing Entra app and Exchange application RBAC assignments.
Do not create duplicate role assignments as part of normal startup or deployment.
Effective `Mail.Read` and `Mail.Send` must be restricted to the phishing mailbox;
Mail.ReadWrite is not needed. Broad Entra grants can be additive to Exchange RBAC.

In an **authorized Exchange Online PowerShell session**, not the Ubuntu shell:

```powershell
Connect-ExchangeOnline
Test-ServicePrincipalAuthorization `
  -Identity "516603e0-ec40-4968-beb9-a57b5d29c1eb" `
  -Resource "phishing@rededucation.com" |
  Format-Table RoleName,GrantedPermissions,InScope
Test-ServicePrincipalAuthorization `
  -Identity "516603e0-ec40-4968-beb9-a57b5d29c1eb" `
  -Resource "dhanush.kumar@rededucation.com" |
  Format-Table RoleName,GrantedPermissions,InScope
```

Expected for this setup: Read/Send `InScope=True` for the phishing mailbox and
`False` for the out-of-scope personal mailbox. The existing custom scope is
`Phishing-Analyzer-Mailbox-Scope`. These checks do not evaluate separate broad
Entra grants; an Exchange administrator should review effective permissions.
PowerShell/Exchange tools are not required to run the Docker worker itself.
See [Exchange application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
and [Graph sendMail](https://learn.microsoft.com/en-us/graph/api/user-sendmail).

## 7. Test, inspect and export results

### End-to-end test

Forward a **new** original email as an `.eml` attachment to
`phishing@rededucation.com` from an allowed internal reporter. In Apple Mail on
Mac, select the original and use **Message → Forward As Attachment**. Inline
forwards lack complete original headers; `.msg`, encrypted messages and archives
are not decoded. Wait for the next poll and check the received analysis reply.

Already processed reports/replies are not automatically reassessed or resent after
updates. Send a new report for fresh AI analysis; do not clear the database to test.

### Offline tests — no API calls or mailbox reads

Tests are in the repository, not bundled into the runtime image. Bind them read-only:

```sh
cd /home/dhanush.kumar/phishing
docker run --rm --network none --read-only --tmpfs /tmp \
  -v /home/dhanush.kumar/phishing/tests:/app/tests:ro \
  phishing-analyzer-analyzer:latest python -m unittest discover -s tests -q
```

For source development on a machine with Python 3.9+:

```sh
python3 -m unittest discover -s tests -q
python3 -m compileall -q app tests
```

Do not start a second live worker on the laptop for development tests.

### Live synthetic acceptance evaluation — eight billable API calls

```sh
cd /home/dhanush.kumar/phishing
docker compose exec -T analyzer python -m app.evaluate --live
```

This uses synthetic examples only, does not read the mailbox or send email, and
makes no automatic retries. These manual calls are outside the collector's daily
cap. Expected: survey, meeting, receipt and Jira notice Safe; password/MFA request,
executable attachment, prompt injection and missing body Suspicious. The policy-v4
acceptance run matched 8/8 with 8,753 tokens; this small set is not a production
accuracy estimate. Offline tests last passed 108 cases.

### Saved reports and reply status — private evidence

```sh
cd /home/dhanush.kumar/phishing
docker compose exec -T analyzer python -m app.replies --status --limit 5
docker compose exec -T analyzer python -m app.replies --limit 3
docker compose exec -T analyzer python -m app.reports --limit 5
docker compose exec -T analyzer python -m app.reports --json --limit 3
```

`--status` hides response bodies but still shows recipients. Reports can contain
subjects, headers, addresses, full defanged links and retained AI usage/coverage.
`ai_analysis` records model, prompt version, usage and coverage; `combined_assessment`
records the policy, result and decision basis. An investigator export computes the
current policy view; the saved AI outcome remains historical.

Export HTML into the volume, then copy it to the VM:

```sh
cd /home/dhanush.kumar/phishing
umask 077
docker compose exec -T analyzer python -m app.reports --limit 5 --format html --output /data/investigation-reports.html
docker compose cp analyzer:/data/investigation-reports.html /home/dhanush.kumar/phishing/investigation-reports.html
chmod 600 /home/dhanush.kumar/phishing/investigation-reports.html
```

Download that export **from your laptop**, if needed:

```sh
scp dhanush.kumar@connect:/home/dhanush.kumar/phishing/investigation-reports.html ./investigation-reports.html
```

The standalone HTML has no scripts or remote resources; links are defanged. Keep
exports private. Use `--format text`/`--format json` and a matching output filename
for other formats. Rerun an export to include newly processed reports.

### Refresh offline findings on saved evidence

Take a backup first. This updates **all saved reports** from retained MIME, keeps
raw MIME/timestamps and historical AI outcomes, and does not fetch mail, call the
API or resend replies. `--limit` limits displayed reports, **not reanalysis scope**.
Stop the worker during this maintenance write:

```sh
cd /home/dhanush.kumar/phishing
docker compose stop analyzer
docker compose run --rm --no-deps -T analyzer python -m app.reports --reanalyze --limit 5
docker compose up -d --no-build analyzer
```

Review errors before resuming normal operation. This does not replace a past
incomplete AI outcome with a fresh AI assessment.

### One live mailbox poll — maintenance use only

This polls Microsoft and can make API calls/send replies according to `.env`.
Do not use it merely to check credentials. Stop the background worker first:

```sh
cd /home/dhanush.kumar/phishing
docker compose stop analyzer
docker compose run --rm --no-deps -T analyzer python -m app.main --once
docker compose up -d --no-build analyzer
```

Exit codes: `0` successful poll, `1` processing/network failure, `2` configuration
or existing-worker-lock error. Check the one-shot exit result before continuing.

## 8. Backup and restore

There is **no scheduled backup job** in this project. The following commands make
manual backups. Keep an additional protected off-VM copy according to your retention
policy; a snapshot stored only in the live volume does not protect against volume loss.
Backups contain private raw emails, replies and AI results. Configuration backups
also contain credentials. Never commit or share them publicly.

### Back up the private configuration

```sh
cd /home/dhanush.kumar/phishing
umask 077
install -d -m 700 /home/dhanush.kumar/phishing-backups
PHISHING_CONFIG_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
install -m 600 .env "/home/dhanush.kumar/phishing-backups/env-$PHISHING_CONFIG_STAMP"
```

### Back up the database consistently while the worker runs

Use SQLite's backup API; copying only a live `.sqlite3` file can miss WAL data.
Run this complete block in the same VM shell:

```sh
cd /home/dhanush.kumar/phishing
umask 077
install -d -m 700 /home/dhanush.kumar/phishing-backups
PHISHING_BACKUP_NAME="reports-$(date -u +%Y%m%dT%H%M%SZ).sqlite3"
docker compose exec -T -e PHISHING_BACKUP_NAME="$PHISHING_BACKUP_NAME" analyzer python - <<'PY'
import os, re, sqlite3
from pathlib import Path
os.umask(0o077)
name = os.environ['PHISHING_BACKUP_NAME']
assert re.fullmatch(r'reports-\d{8}T\d{6}Z\.sqlite3', name)
path = Path('/data') / name
assert not path.exists(), 'Choose a new timestamp; do not replace an existing backup'
source = sqlite3.connect('file:/data/reports.sqlite3?mode=ro', uri=True)
target = sqlite3.connect(str(path))
source.backup(target)
assert target.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
print('Database backup integrity: ok')
target.close()
source.close()
PY
```

If that reports success, copy it outside the Docker volume and verify the copy:

```sh
docker compose cp "analyzer:/data/$PHISHING_BACKUP_NAME" "/home/dhanush.kumar/phishing-backups/$PHISHING_BACKUP_NAME"
chmod 600 "/home/dhanush.kumar/phishing-backups/$PHISHING_BACKUP_NAME"
sha256sum "/home/dhanush.kumar/phishing-backups/$PHISHING_BACKUP_NAME"
python3 - "/home/dhanush.kumar/phishing-backups/$PHISHING_BACKUP_NAME" <<'PY'
import sqlite3, sys
from pathlib import Path
uri = Path(sys.argv[1]).resolve().as_uri() + '?mode=ro'
db = sqlite3.connect(uri, uri=True)
assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
print('Off-volume backup integrity: ok')
db.close()
PY
```

After verifying the copied file, remove only this temporary in-volume snapshot:

```sh
test -n "$PHISHING_BACKUP_NAME" && docker compose exec -T analyzer rm -- "/data/$PHISHING_BACKUP_NAME"
```

Keep the host backup and copy it to approved protected off-VM storage as required.
Do not remove `reports.sqlite3`, `reports.sqlite3-wal`, `reports.sqlite3-shm`, the
worker lock or any state tables during normal maintenance.

### Restore a database — intentional recovery only

Restoring an old snapshot rolls back processed IDs, accepted replies, AI jobs and
activation state. Messages handled after that snapshot may look new again.
**Restore in preview mode with AI off, then reconcile history/pending jobs before
re-enabling sending.** Never reset uncertain jobs blindly.

1. Verify the backup and retain a current backup/configuration copy first.
2. Edit `.env`: set `AUTO_REPLY_MODE=preview` and `AI_ANALYSIS_MODE=off`.
3. Stop the worker and replace the placeholder below with the actual backup name.

```sh
cd /home/dhanush.kumar/phishing
nano .env
chmod 600 .env
docker compose stop analyzer
```

Restore from the protected backup directory. This command validates the source,
saves a pre-restore database snapshot, and uses SQLite backup rather than deleting
journal files. It must run while **all workers using this volume are stopped**.

```sh
PHISHING_RESTORE_FILE='reports-REPLACE-WITH-TIMESTAMP.sqlite3'
docker run --rm -i --network none --read-only --tmpfs /tmp --user 0:0 \
  -e PHISHING_RESTORE_FILE="$PHISHING_RESTORE_FILE" \
  -v phishing-analyzer_analyzer-data:/data \
  -v /home/dhanush.kumar/phishing-backups:/backup:ro \
  --entrypoint python phishing-analyzer-analyzer:latest - <<'PY'
import os, re, sqlite3
from datetime import datetime, timezone
from pathlib import Path
os.umask(0o077)
name = os.environ['PHISHING_RESTORE_FILE']
assert re.fullmatch(r'reports-\d{8}T\d{6}Z\.sqlite3', name), 'Set the real backup filename'
source_path = Path('/backup') / name
source = sqlite3.connect(source_path.as_uri() + '?mode=ro', uri=True)
assert source.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
required = {'reports', 'reply_outbox', 'ai_jobs', 'settings'}
tables = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
assert required <= tables, 'Use a compatible complete analyzer backup'
target_path = Path('/data/reports.sqlite3')
if target_path.exists():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    previous_path = Path('/data') / ('pre-restore-' + stamp + '.sqlite3')
    assert not previous_path.exists()
    current = sqlite3.connect(target_path.as_uri() + '?mode=ro', uri=True)
    previous = sqlite3.connect(str(previous_path))
    current.backup(previous)
    assert previous.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    previous.close()
    current.close()
    os.chown(previous_path, 10001, 10001)
target = sqlite3.connect(str(target_path))
source.backup(target)
assert target.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
target.close()
source.close()
os.chown('/data', 10001, 10001)
os.chmod('/data', 0o700)
for suffix in ('', '-wal', '-shm'):
    path = Path(str(target_path) + suffix)
    if path.exists():
        os.chown(path, 10001, 10001)
        os.chmod(path, 0o600)
print('Restore verified. Start in preview mode with AI off; reconcile before enabling send.')
PY
```

After a successful restore, start with the edited safe maintenance modes:

```sh
cd /home/dhanush.kumar/phishing
docker compose up -d --no-build --force-recreate analyzer
docker compose exec -T analyzer python -m app.ai_check
docker compose exec -T analyzer python -m app.replies --status
docker compose logs --tail=50 analyzer
```

Confirm AI is off and startup logs show reply mode preview. Review newer messages,
Sent Items/message tracing, and pending/uncertain jobs. Only after reconciliation,
edit `.env` back to intended modes and force-recreate. Pending preview replies may
then be sent; do not re-enable send as an automatic final restore step.

### Recovering on a replacement VM

Install Docker Engine and Compose using the [official Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/).
On a replacement VM with no checkout yet, create it with:

```sh
git clone https://github.com/RedEd-DK/phishing-analyzer.git /home/dhanush.kumar/phishing
cd /home/dhanush.kumar/phishing
chmod 700 /home/dhanush.kumar/phishing
```

Copy the approved configuration backup and database backup into the protected
backup directory through your organization's recovery process. Install the selected
configuration backup as `.env`; replace the timestamp below. Do this only on the
replacement checkout where no `.env` exists:

```sh
cd /home/dhanush.kumar/phishing
PHISHING_ENV_BACKUP='/home/dhanush.kumar/phishing-backups/env-REPLACE-WITH-TIMESTAMP'
test ! -e .env && install -m 600 "$PHISHING_ENV_BACKUP" .env
nano .env
```

Set `COMPOSE_PROJECT_NAME=phishing-analyzer`, `AUTO_REPLY_MODE=preview` and
`AI_ANALYSIS_MODE=off` before starting recovery. Build the image and create the
empty volume, then follow the restore procedure above:

```sh
cd /home/dhanush.kumar/phishing
docker compose build analyzer
docker volume create phishing-analyzer_analyzer-data
```

Do not start a fresh production worker on the replacement VM before restoring
history and stopping the old host.

For a **completely new installation with no prior history**, after cloning, use
this alternative configuration step instead of installing a recovery backup:

```sh
cd /home/dhanush.kumar/phishing
if [ ! -e .env ]; then install -m 600 .env.example .env; fi
nano .env
chmod 600 .env
```

Fill in credentials, add `COMPOSE_PROJECT_NAME=phishing-analyzer`, choose intended
modes/model, then `docker compose up -d --build analyzer`. The template defaults
to preview replies and AI off; it is not the current production configuration.

## 9. Troubleshooting

| Symptom | Check/action |
| --- | --- |
| Cannot SSH; VM is off | Power on through VMware; then check network/DNS/VPN access to `connect` |
| Docker daemon unavailable | `systemctl is-active docker`; start Docker as in section 3 |
| Docker socket permission denied | Use the authorized VM account/Docker group; do not make the socket world-writable |
| Container exits/restarts | `docker compose ps -a`, then `docker compose logs --tail=100 analyzer` |
| Invalid configuration | Check required `.env` values/numeric limits privately; force-recreate after editing |
| Graph 401 | Expired/invalid Entra secret or tenant/application settings; check Entra sign-in diagnostics |
| Graph 403 / reply blocked | Effective Mail.Read/Mail.Send scope; ask Exchange admin; permission propagation may take time |
| AI unavailable | `app.ai_check`; API key, API billing, selected-model access, network and daily cap |
| AI test succeeds, automatic AI off | Set `AI_ANALYSIS_MODE=on` and recreate; test success does not enable the mode |
| No new report | Inbox only; already processed IDs are skipped; check next poll, message size and MIME limits |
| No reply | Check mode, exact reporter domain, outbox reason, activation time, loop rules and hourly limit |
| Reply accepted but not received | Accepted means Graph 202, not delivery; check Sent Items/Exchange tracing |
| Reply uncertain | Check Sent Items/tracing; no automatic retry to avoid duplicates |
| Another worker owns the volume | Stop the duplicate; do not delete `worker.lock` to bypass the lock |
| Safe expected, Suspicious returned | Read its reason/AI coverage; missing essential content or unavailable AI requires review |
| Disk usage increasing | `df -h /home/dhanush.kumar/phishing`, `docker system df`; inspect backups/exports privately |

Useful targeted runtime checks (no credentials printed):

```sh
cd /home/dhanush.kumar/phishing
docker inspect phishing-analyzer-analyzer-1 --format 'status={{.State.Status}} restart_policy={{.HostConfig.RestartPolicy.Name}} restarts={{.RestartCount}}'
docker compose exec -T analyzer python -c 'from app.decision import POLICY_VERSION; from app.ai_analysis import PROMPT_VERSION; print(dict(policy_version=POLICY_VERSION, prompt_version=PROMPT_VERSION))'
df -h /home/dhanush.kumar/phishing
docker system df
```

There is no automatic evidence deletion, independent uptime monitoring or scheduled
backup configured by this repository. Plan those separately. Container restart
is process recovery, not proof that the API or email delivery is healthy.

## 10. Analysis behavior and safeguards

### Workflow and limits

Only the current Inbox is scanned, across all pages, normally every 60 seconds.
Read status does not matter. Messages moved out before polling can be missed.
Immutable Graph message IDs and SQLite keep processing idempotent across restarts.
Raw MIME, complete extracted headers, bodies, URLs, hashes and originals are retained.
MIME size defaults to 25 MiB; traversal is capped at depth 8 and 1,000 parts.

Only the **outer reporting sender** on an exact allowed domain receives a reply.
Never the suspect original sender, outer Reply-To, reply-all, or Security by default.
Automatic/list/bounce/no-reply/service messages are suppressed. First activation
stores persistent timestamps to skip reply/AI backfill of historical Inbox mail.
Preview pending replies received after activation can be sent when send is enabled.

The response has HTML/plain-text alternatives, defanged suspect links, no remote
images/fonts/scripts/pixels, bounded details and a `mailto:` Contact Security action.
That button opens a new email; it does not forward or escalate the report.
Original attachments are never included in the automated response.

### Two results

- **SAFE** (green): AI supports legitimate context at medium/high confidence,
  complete material original coverage, no material blockers and low policy risk.
- **SUSPICIOUS** (red): actual warning signs, unresolved sensitive actions, missing
  essential evidence, low confidence or unavailable analysis requires review.
  Its explanation distinguishes a warning from an inability to clear the message.

Safe is an assessment, not an authenticity certificate or malware-scan result.
There is no separate Unable to determine headline. Internal AI labels can still
record uncertainty. Missing authentication headers, ordinary signature images,
and routine deadlines alone are not phishing evidence. Internal domains and
familiar platforms are not unconditional allowlists.

Versioned weighted checks cover sender/reply differences, URL deception, executable/
active files, sensitive requests, and prompt-injection attempts. Related duplicate
findings count once per family per original. Strong signals cannot be cancelled
by benign AI prose. Missing original/body or omitted material evidence prevents
Safe; shortening only unverified diagnostic headers does not. Both plaintext and
differing HTML alternatives are considered. Policy points are heuristics, not
calibrated probabilities; see `app/decision.py` and the regression tests.

### OpenAI data and cost boundaries

The fixed API endpoint is `https://api.openai.com/v1/responses`. Inputs include up
to six bounded originals, relevant text, selected unverified headers, navigational
links, resource-domain summaries, attachment metadata and offline findings.
Attachment binaries/raw MIME, Received routing headers, Message-IDs and local
credentials are excluded. Email local parts and URL user-info/query/fragments are
removed; names, body content and URL paths can still contain sensitive data.
This is disclosure reduction, not complete anonymization.

Inputs have a character bound plus instruction/schema overhead. Actual input,
output and available reasoning-token counts are retained; reasoning tokens are
part of output, not an extra total to add again. The daily limit bounds automatic
attempts, not dollar spend. Network-unknown outcomes may incur unrecorded charges.
Manual diagnostics are additional calls. No model tools, browsing, conversation
history, link visits or executable attachment access are provided to the model.
Untrusted email instructions cannot set recipients or directly send mail.

Requests use `store=false`; that does not guarantee zero retention. Default abuse
monitoring can retain content for up to 30 days subject to exceptions. API content
is not used for model training by default unless you opt in. Review your
organization's data policy and [OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data).
No live URL reputation, independent SPF/DKIM/DMARC validation, sender-history feed,
attachment malware scanning or archive decoding is integrated.

### Durable delivery and AI jobs

| Reply state | Meaning |
| --- | --- |
| `pending` | Prepared, waiting or preview mode |
| `sending` | Claimed before send; interruption is recovered as uncertain |
| `accepted` | Graph accepted submission; delivery not confirmed |
| `retry` | Throttled/rejected before submission; eligible after delay |
| `blocked` | Authorization problem; retry after delay |
| `skipped` | Activation, sender eligibility or loop prevention |
| `uncertain` | Send outcome unknown; no automatic retry |
| `failed` | Permanent rejection; manual review |

At most 20 ready replies are attempted per poll, subject to per-recipient limits.
A durable reservation precedes each automatic AI attempt. Outcomes persist before
reply queueing. Requests with failed/unknown results are not blindly retried.
Exactly-once email delivery is not claimed. Do not delete state, reset jobs or
manually replay outbox rows to force a result.

## 11. Agent and source documentation

[AGENTS.md](AGENTS.md) defines repository/deployment rules for coding agents.
[agent.md](agent.md) is a compatibility pointer to that canonical file.

Python standard library only; the Dockerfile builds Python 3.12 slim with user
`10001:10001`. Compose uses a read-only root filesystem, temporary `/tmp`, dropped
capabilities, no-new-privileges, bounded memory/CPU/PIDs and rotated container logs.
Credentials/evidence are ignored by Git and excluded from the Docker build context.

Implementation references:
[Microsoft OAuth client credentials](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow),
[Graph MIME retrieval](https://learn.microsoft.com/en-us/graph/outlook-get-mime-message),
[OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs),
[Docker Compose](https://docs.docker.com/compose/),
[Microsoft holistic spoof evaluation](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-spoofing-about),
[SpamAssassin weighted tests](https://spamassassin.apache.org/full/4.0.x/doc/Mail_SpamAssassin_Conf.html).
