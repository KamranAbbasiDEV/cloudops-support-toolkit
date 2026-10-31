"""Read-only HTTP, DNS and TLS diagnostics."""
from __future__ import annotations
import datetime as dt
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

SEVERITY = {"ok": 0, "skipped": 0, "warning": 1, "critical": 2}

def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

def _public_url(parsed: urllib.parse.SplitResult) -> str:
    hostname = parsed.hostname or ""
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{hostname}{port}{parsed.path or '/'}"

def check_dns(hostname: str) -> dict:
    try:
        answers = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        addresses = sorted({address[4][0] for address in answers})
        if not addresses:
            return {"name": "dns", "status": "critical", "detail": "No IP addresses returned"}
        return {"name": "dns", "status": "ok", "addresses": addresses}
    except OSError as exc:
        return {"name": "dns", "status": "critical", "detail": str(exc)}

def check_http(url: str, timeout: float) -> dict:
    started = time.monotonic()
    request = urllib.request.Request(url, headers={"User-Agent": "CloudOps-Support-Toolkit/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status_code = response.status
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        exc.close()
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        return {"name": "http", "status": "critical", "detail": str(exc),
                "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    result_status = "ok" if 200 <= status_code < 400 else ("warning" if 400 <= status_code < 500 else "critical")
    return {"name": "http", "status": result_status, "status_code": status_code,
            "latency_ms": round((time.monotonic() - started) * 1000, 1)}

def check_tls(hostname: str, port: int, timeout: float, warn_days: int) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                certificate = tls_socket.getpeercert()
        expiry_seconds = ssl.cert_time_to_seconds(certificate["notAfter"])
        expiry = dt.datetime.fromtimestamp(expiry_seconds, tz=dt.timezone.utc)
        days_left = (expiry - dt.datetime.now(dt.timezone.utc)).total_seconds() / 86400
        return {"name": "tls", "status": "warning" if days_left <= warn_days else "ok",
                "expires_at_utc": expiry.isoformat(timespec="seconds"),
                "days_until_expiry": round(days_left, 1), "warn_threshold_days": warn_days}
    except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
        return {"name": "tls", "status": "critical", "detail": str(exc)}

def run_checks(url: str, timeout: float = 5.0, warn_days: int = 30) -> dict:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be a valid http:// or https:// URL with a hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    if not 0 < timeout <= 120:
        raise ValueError("Timeout must be greater than 0 and at most 120 seconds")
    if warn_days < 0:
        raise ValueError("warn-days cannot be negative")
    if parsed.username or parsed.password:
        raise ValueError("Do not put credentials in the URL")
    checks = [check_dns(parsed.hostname)]
    if parsed.scheme.lower() == "https":
        checks.append(check_tls(parsed.hostname, port or 443, timeout, warn_days))
    else:
        checks.append({"name": "tls", "status": "skipped", "detail": "HTTP URL; TLS not used"})
    checks.append(check_http(url, timeout))
    overall = max(checks, key=lambda check: SEVERITY[check["status"]])["status"]
    return {"schema_version": 1, "checked_at_utc": _utc_now(), "target": _public_url(parsed),
            "overall_status": overall, "checks": checks}
