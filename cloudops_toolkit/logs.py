"""Summarize Apache/Nginx common/combined HTTP access logs."""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import re
from urllib.parse import urlsplit

REQUEST = re.compile(r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[0-9.]+"\s+(?P<status>[1-5][0-9]{2})(?:\s|$)')

def _normalized_path(request_target: str) -> str:
    parsed = urlsplit(request_target)
    return (parsed.path or "/")[:200]

def analyze_access_log(path: str | Path, top: int = 5) -> dict:
    if top < 1:
        raise ValueError("top must be at least 1")
    statuses: Counter[str] = Counter()
    error_paths: Counter[str] = Counter()
    total = 0
    parsed_count = 0
    with Path(path).open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            total += 1
            match = REQUEST.search(line)
            if not match:
                continue
            parsed_count += 1
            code = match.group("status")
            statuses[code] += 1
            if code.startswith(("4", "5")):
                error_paths[_normalized_path(match.group("path"))] += 1
    return {"source": str(path), "total_lines": total, "parsed_requests": parsed_count,
            "unparsed_lines": total - parsed_count,
            "http_4xx": sum(count for code, count in statuses.items() if code.startswith("4")),
            "http_5xx": sum(count for code, count in statuses.items() if code.startswith("5")),
            "status_codes": dict(sorted(statuses.items())),
            "top_error_paths": [{"path": name, "errors": count} for name, count in error_paths.most_common(top)]}
