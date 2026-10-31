from pathlib import Path
import tempfile
import unittest
from cloudops_toolkit.logs import analyze_access_log
SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "access.log"

class TestLogAnalysis(unittest.TestCase):
    def test_sample_counts(self):
        result = analyze_access_log(SAMPLE)
        self.assertEqual(result["parsed_requests"], 10)
        self.assertEqual(result["http_5xx"], 4)
        self.assertEqual(result["http_4xx"], 2)
        self.assertEqual(result["top_error_paths"][0], {"path": "/api/orders", "errors": 4})
    def test_malformed_lines_are_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            path.write_text('invalid line\n127.0.0.1 - - "GET / HTTP/1.1" 200 1\n', encoding="utf-8")
            result = analyze_access_log(path)
        self.assertEqual(result["unparsed_lines"], 1)
        self.assertEqual(result["parsed_requests"], 1)
    def test_query_parameters_not_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            path.write_text('127.0.0.1 - - "GET /orders?token=secret HTTP/1.1" 500 1\n', encoding="utf-8")
            result = analyze_access_log(path)
        self.assertEqual(result["top_error_paths"][0]["path"], "/orders")
