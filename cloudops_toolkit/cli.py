"""Command-line interface for support diagnostics and triage reports."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from .checks import run_checks
from .logs import analyze_access_log
from .reports import build_incident_report

def _json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"

def _write(path: str | None, content: str) -> None:
    if path:
        Path(path).write_text(content, encoding="utf-8")
    else:
        print(content, end="")

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cloudops", description="Read-only HTTP, DNS, TLS and log triage utilities")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="Check URL health, DNS and TLS expiry")
    check.add_argument("url", help="e.g. https://example.com")
    check.add_argument("--timeout", type=float, default=5.0, help="seconds (default: 5)")
    check.add_argument("--warn-days", type=int, default=30, help="TLS warning threshold")
    check.add_argument("--output", help="optional destination for JSON")
    logs = sub.add_parser("analyze-logs", help="Summarize Apache/Nginx access logs")
    logs.add_argument("path", help="path to access.log")
    logs.add_argument("--top", type=int, default=5, help="top error endpoints")
    logs.add_argument("--output", help="optional destination for JSON")
    report = sub.add_parser("incident-report", help="Generate initial Markdown triage report")
    report.add_argument("--health", required=True, help="JSON from check or demo sample")
    report.add_argument("--logs", required=True, help="Apache/Nginx access log")
    report.add_argument("--output", help="destination .md file (or stdout)")
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            data = run_checks(args.url, args.timeout, args.warn_days)
            _write(args.output, _json(data))
            return {"ok": 0, "warning": 1, "critical": 2}[data["overall_status"]]
        if args.command == "analyze-logs":
            _write(args.output, _json(analyze_access_log(args.path, args.top)))
            return 0
        if args.command == "incident-report":
            health = json.loads(Path(args.health).read_text(encoding="utf-8"))
            log_summary = analyze_access_log(args.logs)
            _write(args.output, build_incident_report(health, log_summary))
            return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 3
    return 3
