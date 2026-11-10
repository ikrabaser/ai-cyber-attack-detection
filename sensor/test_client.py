import contextlib
import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import detect as detect_cli
from client import build_event, send_event
from features import FEATURES, extract
from rules import detect
from zeek_reader import read_log

SAMPLE = Path(__file__).parent / "sample" / "conn.log"
TOKEN = "good-token"


class FakeBackend(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._reply(401, {"error": "yetkisiz"})
        self.received.append(body)
        if body["risk_score"] < 0.5:
            return self._reply(200, {"status": "ignored"})
        self._reply(201, {"status": "created", "event_id": len(self.received)})

    def _reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakeBackend)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/api/events/"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        FakeBackend.received.clear()
        self.found = detect(extract(read_log(SAMPLE)))

    def test_payload_has_what_the_backend_needs(self):
        payload = build_event(self.found[0])
        self.assertEqual(payload["source_ip"], "192.168.56.200")
        self.assertEqual(payload["target_host"], "192.168.56.20")
        self.assertEqual(payload["attack_type"], "port_scan")
        self.assertEqual(payload["risk_score"], 0.99)
        self.assertIn("40 farklı porta", payload["summary"])
        for name in FEATURES:
            self.assertIn(name, payload["features"])
        self.assertIn("window_start", payload["features"])
        json.dumps(payload)  # JSON'a çevrilebilir olmalı

    def test_send_event_success(self):
        status, body = send_event(self.url, TOKEN, build_event(self.found[0]))
        self.assertEqual((status, body["status"]), (201, "created"))
        self.assertEqual(FakeBackend.received[0]["attack_type"], "port_scan")

    def test_wrong_token_returns_401_without_raising(self):
        status, body = send_event(self.url, "wrong", build_event(self.found[0]))
        self.assertEqual(status, 401)
        self.assertEqual(FakeBackend.received, [])

    def test_cli_dry_run_sends_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = detect_cli.main([str(SAMPLE)])
        self.assertEqual(code, 0)
        self.assertEqual(FakeBackend.received, [])
        self.assertIn("7 tespit", out.getvalue())

    def test_cli_send_posts_every_detection(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = detect_cli.main([str(SAMPLE), "--send", "--url", self.url, "--token", TOKEN])
        self.assertEqual(code, 0)
        self.assertEqual(len(FakeBackend.received), 7)

    def test_cli_bad_token_stops_with_error(self):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = detect_cli.main([str(SAMPLE), "--send", "--url", self.url, "--token", "nope"])
        self.assertEqual(code, 1)
        self.assertIn("Token reddedildi", err.getvalue())

    def test_cli_unreachable_backend_is_reported(self):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = detect_cli.main([str(SAMPLE), "--send", "--url", "http://127.0.0.1:9/api/events/",
                                    "--token", TOKEN])
        self.assertEqual(code, 1)
        self.assertIn("ulaşılamadı", err.getvalue())


if __name__ == "__main__":
    unittest.main()
