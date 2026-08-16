"""Smoke + functional tests for the in-house vulnerability scanner.

Run with:  make test-scan   (or)   pytest tests/test_scanner.py -q
"""

import os
import sys
import socket
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import Scanner, ScanResult  # noqa: E402
from scanner.report import to_html, to_json  # noqa: E402


class _Handler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = (
            "<html><body>"
            "<a href='/about'>about</a>"
            "<form action='/search'><input name='q'></form>"
            "</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


@pytest.fixture()
def target_url():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}/"
    srv.shutdown()


def test_crawler_discovers_links(target_url):
    result = Scanner(max_pages=5, timeout=3).run(target_url, "Passive Scan")
    assert len(result.crawled_urls) >= 1
    assert result.finished_at >= result.started_at


def test_passive_checks_produce_findings(target_url):
    result = Scanner(max_pages=5, timeout=3).run(target_url, "Passive Scan")
    titles = [f.title for f in result.findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("Insecure transport" in t for t in titles)


def test_report_renderers(target_url):
    result = Scanner(max_pages=5, timeout=3).run(target_url, "Passive Scan")
    d = result.to_dict()
    html = to_html(d)
    assert "GuardianSecure Scan Report" in html
    assert isinstance(to_json(d), dict)


def test_active_scan_runs(target_url):
    result = Scanner(max_pages=3, timeout=3).run(target_url, "Active Scan")
    assert result.summary() is not None
