import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from scanner.cli import main


class LocalHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            "/.env": (200, b"SECRET_KEY=test-secret"),
            "/admin": (403, b"Forbidden"),
            "/missing": (404, b"Not Found"),
        }

        status, body = routes.get(
            self.path,
            (404, b"Not Found"),
        )

        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def test_cli_end_to_end(tmp_path, monkeypatch):
    server = HTTPServer(
        ("127.0.0.1", 0),
        LocalHTTPHandler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    try:
        port = server.server_address[1]

        wordlist = tmp_path / "paths.txt"
        wordlist.write_text(
            ".env\n"
            "admin\n"
            "missing\n",
            encoding="utf-8",
        )

        json_report = tmp_path / "scan.json"
        text_report = tmp_path / "scan.txt"

        monkeypatch.setattr(
            "sys.argv",
            [
                "cli.py",
                "--url",
                f"http://127.0.0.1:{port}",
                "--wordlist",
                str(wordlist),
                "--json",
                str(json_report),
                "--text",
                str(text_report),
            ],
        )

        exit_code = main()

        assert exit_code == 0
        assert json_report.exists()
        assert text_report.exists()

        report = json.loads(
            json_report.read_text(encoding="utf-8")
        )

        assert report["target"] == f"http://127.0.0.1:{port}"
        assert report["wordlist_size"] == 3
        assert report["requests_sent"] == 3

        assert report["summary"]["total_findings"] == 3
        assert report["summary"]["critical"] == 1
        assert report["summary"]["low"] == 1

        rule_ids = {
            finding["rule_id"]
            for finding in report["findings"]
        }

        assert "DIRECTORY_200" in rule_ids
        assert "SENSITIVE_EXPOSURE" in rule_ids
        assert "DIRECTORY_403" in rule_ids

        text = text_report.read_text(
            encoding="utf-8"
        )

        assert "DAY 20 - WEB DIRECTORY DISCOVERY SCAN" in text
        assert "SENSITIVE_EXPOSURE" in text
        assert "CRITICAL" in text
        assert ".env" in text
        assert "Remove sensitive files" in text

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
