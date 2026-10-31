import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from cloudops_toolkit.checks import check_dns, check_http, run_checks

class TestChecks(unittest.TestCase):
    def test_dns_deduplicates_addresses(self):
        with patch("cloudops_toolkit.checks.socket.getaddrinfo") as lookup:
            lookup.return_value = [(2, 1, 6, "", ("192.0.2.1", 0)), (2, 1, 6, "", ("192.0.2.1", 0)), (2, 1, 6, "", ("192.0.2.2", 0))]
            result = check_dns("example.com")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["addresses"], ["192.0.2.1", "192.0.2.2"])
    def test_http_503_is_critical(self):
        err = HTTPError("https://example.com", 503, "Service unavailable", {}, io.BytesIO())
        with patch("cloudops_toolkit.checks.urllib.request.urlopen", side_effect=err):
            result = check_http("https://example.com", timeout=1)
        self.assertEqual(result["status"], "critical")
        self.assertEqual(result["status_code"], 503)
    def test_url_query_hidden_in_report(self):
        with patch("cloudops_toolkit.checks.check_dns", return_value={"name": "dns", "status": "ok"}), patch("cloudops_toolkit.checks.check_tls", return_value={"name": "tls", "status": "ok"}), patch("cloudops_toolkit.checks.check_http", return_value={"name": "http", "status": "ok"}):
            result = run_checks("https://example.com/health?secret=my-private-token")
        self.assertEqual(result["target"], "https://example.com/health")
        self.assertEqual(result["overall_status"], "ok")
    def test_invalid_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            run_checks("file:///etc/passwd")
    def test_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            run_checks("https://user:pass@example.com")
    def test_http_url_skips_tls(self):
        with patch("cloudops_toolkit.checks.check_dns", return_value={"name": "dns", "status": "ok"}), patch("cloudops_toolkit.checks.check_http", return_value={"name": "http", "status": "warning"}):
            result = run_checks("http://example.com")
        self.assertEqual(result["overall_status"], "warning")
        self.assertEqual(result["checks"][1]["status"], "skipped")
