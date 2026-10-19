"""Inspect automatic reply status and exact stored response text; sends nothing."""
import argparse
import json
import os
import sqlite3
from email import policy
from email.parser import BytesParser
from pathlib import Path

from .investigation_report import display


def main():
    parser = argparse.ArgumentParser(description="Inspect response outbox without sending mail")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--status", action="store_true", help="Hide stored response bodies")
    args = parser.parse_args()
    if not 1 <= args.limit <= 100:
        parser.error("--limit must be between 1 and 100")
    path = Path(os.environ.get("DATA_DIR", "data")) / "reports.sqlite3"
    try:
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        counts = dict(db.execute("SELECT state,count(*) FROM reply_outbox GROUP BY state"))
        rows = db.execute("SELECT recipient,state,reason,mime FROM reply_outbox ORDER BY updated_at DESC LIMIT ?", (args.limit,)).fetchall()
    except sqlite3.Error:
        print("Reply outbox unavailable. Start the updated collector first.")
        return 1
    finally:
        if "db" in locals():
            db.close()
    print("REPLY STATUS: " + json.dumps(counts, sort_keys=True))
    for recipient, state, reason, raw in rows:
        print("\nRecipient: " + display(recipient))
        print("State: " + display(state) + "; reason: " + display(reason))
        if raw and not args.status:
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            print("Subject: " + display(msg["Subject"]))
            print("\n" + msg.get_content())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
