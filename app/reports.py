"""Inspect saved findings or refresh analysis from locally retained MIME."""
import argparse
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from .email_parser import analyze
from .investigation_report import render_html, render_text


def reanalyze(db):
    updated = failed = 0
    for mailbox, message_id, raw, saved in db.execute("SELECT mailbox,message_id,raw_mime,report_json FROM reports"):
        try:
            result = analyze(raw)
            previous = json.loads(saved)
            if "ai_analysis" in previous:
                result["ai_analysis"] = previous["ai_analysis"]
                from .decision import decision_record
                result["combined_assessment"] = decision_record(result)
            with db:
                db.execute("UPDATE reports SET report_json=? WHERE mailbox=? AND message_id=?",
                           (json.dumps(result, ensure_ascii=True), mailbox, message_id))
            updated += 1
        except Exception as exc:
            print(json.dumps({"reanalysis_error": type(exc).__name__}), file=sys.stderr)
            failed += 1
    return {"updated": updated, "failed": failed}


def summary(report):
    return {"subject": report.get("subject"), "from": report.get("from"),
            "assessment": report.get("assessment", {"status": "Run --reanalyze to add findings"}),
            "originals": [summary(item) for item in report.get("originals", [])]}


def main():
    parser = argparse.ArgumentParser(description="Show locally stored security findings")
    parser.add_argument("--reanalyze", action="store_true", help="Refresh all saved reports from retained MIME; no Graph requests")
    parser.add_argument("--limit", type=int, default=5)
    formats = parser.add_mutually_exclusive_group()
    formats.add_argument("--json", action="store_true", help="Include all extracted evidence as JSON")
    formats.add_argument("--format", choices=("text", "html", "json"), default="text", help="Report format (default: readable text)")
    parser.add_argument("--output", type=Path, help="Save to a local file instead of printing")
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000:
        parser.error("--limit must be between 1 and 1000")
    path = Path(os.environ.get("DATA_DIR", "data")) / "reports.sqlite3"
    try:
        db = sqlite3.connect(path.resolve().as_uri() + ("?mode=rw" if args.reanalyze else "?mode=ro"), uri=True)
    except sqlite3.Error:
        print("No accessible reports database. Process a message first and check DATA_DIR.")
        return 1
    failed = 0
    try:
        if args.reanalyze:
            counts = reanalyze(db)
            failed = counts["failed"]
            print(json.dumps({"reanalysis": counts}), file=sys.stderr)
        records = []
        for received, processed, payload in db.execute(
                "SELECT received_at,processed_at,report_json FROM reports ORDER BY processed_at DESC,rowid DESC LIMIT ?", (args.limit,)):
            report = json.loads(payload)
            records.append({"received_at": received, "processed_at": processed, "report": report})
        format_name = "json" if args.json else args.format
        if format_name == "html":
            content = render_html(records)
        elif format_name == "text":
            content = render_text(records)
        else:
            content = json.dumps(records, indent=2, ensure_ascii=True) + "\n"
        if args.output:
            save_output(args.output, content)
            print("Saved investigation report.")
        else:
            print(content, end="")
    finally:
        db.close()
    return 1 if failed else 0


def save_output(path, content):
    """Use a private temporary file and replace atomically; never name from email data."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
