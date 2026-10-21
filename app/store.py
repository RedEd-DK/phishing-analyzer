import json
import sqlite3
import time


class Store:
    def __init__(self, directory):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(str(directory / "reports.sqlite3"))
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS reports (
            mailbox TEXT NOT NULL, message_id TEXT NOT NULL,
            received_at TEXT, processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            report_json TEXT NOT NULL, raw_mime BLOB NOT NULL,
            PRIMARY KEY (mailbox, message_id))""")
        self.db.commit()
        self.db.execute("""CREATE TABLE IF NOT EXISTS reply_outbox (
            mailbox TEXT NOT NULL, message_id TEXT NOT NULL, recipient TEXT,
            mime BLOB, state TEXT NOT NULL, reason TEXT,
            created_at REAL NOT NULL, updated_at REAL NOT NULL, next_attempt REAL NOT NULL DEFAULT 0,
            PRIMARY KEY (mailbox,message_id))""")
        self.db.execute("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS ai_jobs (
            mailbox TEXT NOT NULL, message_id TEXT NOT NULL, created_at REAL NOT NULL,
            attempted INTEGER NOT NULL, result_json TEXT, model TEXT NOT NULL,
            PRIMARY KEY (mailbox,message_id))""")
        self.db.commit()

    def ai_activation(self, mailbox):
        key = "ai_activation:" + mailbox.lower()
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (key, str(time.time())))
        return float(self.db.execute("SELECT value FROM settings WHERE name=?", (key,)).fetchone()[0])

    def reply_activation(self, mailbox):
        key = "reply_activation:" + mailbox.lower()
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (key, str(time.time())))
        return float(self.db.execute("SELECT value FROM settings WHERE name=?", (key,)).fetchone()[0])

    def report(self, mailbox, message_id):
        row = self.db.execute("SELECT report_json FROM reports WHERE mailbox=? AND message_id=?",
                              (mailbox.lower(), message_id)).fetchone()
        return json.loads(row[0]) if row else None

    def queue_reply(self, mailbox, message_id, recipient, mime, state, reason):
        now = time.time()
        with self.db:
            self.db.execute("""INSERT OR IGNORE INTO reply_outbox
                (mailbox,message_id,recipient,mime,state,reason,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?)""", (mailbox.lower(), message_id, recipient, mime, state, reason, now, now))

    def recover_replies(self):
        with self.db:
            self.db.execute("UPDATE reply_outbox SET state='uncertain',reason='interrupted_send',updated_at=? WHERE state='sending'", (time.time(),))

    def claim_reply(self, mailbox, message_id):
        with self.db:
            cursor = self.db.execute("""UPDATE reply_outbox SET state='sending',updated_at=?
                WHERE mailbox=? AND message_id=? AND state IN ('pending','retry','blocked')""",
                (time.time(), mailbox.lower(), message_id))
        return cursor.rowcount == 1

    def finish_reply(self, mailbox, message_id, state, reason=None, delay=0):
        now = time.time()
        with self.db:
            self.db.execute("UPDATE reply_outbox SET state=?,reason=?,updated_at=?,next_attempt=? WHERE mailbox=? AND message_id=?",
                            (state, reason, now, now + delay, mailbox.lower(), message_id))

    def contains(self, mailbox, message_id):
        return self.db.execute("SELECT 1 FROM reports WHERE mailbox=? AND message_id=?",
                               (mailbox.lower(), message_id)).fetchone() is not None

    def save(self, mailbox, message, raw, report):
        # Raw evidence, extracted originals, and deduplication marker commit together.
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO reports (mailbox,message_id,received_at,report_json,raw_mime) VALUES (?,?,?,?,?)",
                            (mailbox.lower(), message["id"], message.get("receivedDateTime"),
                             json.dumps(report, ensure_ascii=True), raw))

    def close(self):
        self.db.close()
