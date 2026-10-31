"""Create a cautious, evidence-based initial incident report."""
from __future__ import annotations
import datetime as dt

def _safe(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

def build_incident_report(health: dict, logs: dict) -> str:
    checks = health.get("checks", [])
    overall = health.get("overall_status", "unknown")
    server_errors = logs.get("http_5xx", 0)
    client_errors = logs.get("http_4xx", 0)
    possible_impact = ("Service errors were observed; customer impact should be verified."
                       if server_errors or overall == "critical"
                       else "No confirmed customer impact from these sample checks.")
    lines = [
        "# Initial Incident Triage Report", "",
        f"- **Generated (UTC):** {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}",
        f"- **Target:** `{_safe(health.get('target', 'not provided'))}`",
        f"- **Health summary:** **{_safe(overall).upper()}**",
        f"- **Impact assessment:** {possible_impact}",
        "- **Root cause:** Unconfirmed — investigate before assigning a cause.",
        "", "## Health-check evidence", "",
        "| Check | Result | Evidence |", "| --- | --- | --- |"
    ]
    for item in checks:
        details = []
        for key in ("status_code", "latency_ms", "days_until_expiry", "detail"):
            if key in item:
                details.append(f"{key}: {_safe(item[key])}")
        lines.append(f"| {_safe(item.get('name', '?'))} | {_safe(item.get('status', '?'))} | {'; '.join(details) or 'See raw JSON'} |")
    lines += ["", "## Access-log evidence", "",
              f"- Parsed requests: **{logs.get('parsed_requests', 0)}**",
              f"- HTTP 4xx responses: **{client_errors}**",
              f"- HTTP 5xx responses: **{server_errors}**",
              f"- Unparsed lines (different log formats): **{logs.get('unparsed_lines', 0)}**",
              "", "| Error endpoint | Count |", "| --- | ---: |"]
    for item in logs.get("top_error_paths", []):
        lines.append(f"| `{_safe(item['path'])}` | {item['errors']} |")
    if not logs.get("top_error_paths"):
        lines.append("| None detected | 0 |")
    lines += ["", "## Recommended investigation", ""]
    steps = []
    if server_errors:
        steps.append("Correlate 5xx timestamps with application/server logs and recent deployments.")
    if any(c.get("name") == "dns" and c.get("status") != "ok" for c in checks):
        steps.append("Verify DNS records, authoritative name servers, and resolver reachability.")
    if any(c.get("name") == "tls" and c.get("status") in {"warning", "critical"} for c in checks):
        steps.append("Verify certificate chain, expiry, and approved renewal procedure.")
    steps += ["Reproduce from a second location, review monitoring dashboards, and check scope of impact.",
              "Record timeline, ownership, updates, and remediation after independent verification."]
    for index, step in enumerate(steps, 1):
        lines.append(f"{index}. {step}")
    lines += ["", "> This is an initial triage document, not a confirmed root-cause analysis.", ""]
    return "\n".join(lines)
