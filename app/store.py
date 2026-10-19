import json
import sqlite3


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
