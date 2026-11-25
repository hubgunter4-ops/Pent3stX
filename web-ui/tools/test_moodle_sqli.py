"""Unit tests for web-ui/tools/moodle_sqli.py (and the server's
moodle-sqli validation, which reuses this module).

These tests never contact a real Moodle and never call pentestx.py.
The only network traffic is against a mock HTTP server started by
the tests themselves on 127.0.0.1:8080, which answers with fake
timing (slow only when the tested character matches). The dry-run
test asserts that zero requests reach the mock.

Run:  python3 -m unittest discover -s web-ui/tools -p "test_moodle_sqli.py" -v
(from the repository root, or: python3 web-ui/tools/test_moodle_sqli.py)
"""

import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import moodle_sqli  # noqa: E402
import server  # noqa: E402

BASE_URL = "http://127.0.0.1:8080/moodle"
SESSKEY = "ZT0E6J0xWe"
COOKIE = "5b1rk2pfdpbcq2i5hmmern1os0"
AUTH = "docs/AUTORIZACION-moodle-local.md"


def base_request(**overrides):
    request = {
        "base_url": BASE_URL,
        "sesskey": SESSKEY,
        "session_cookie": COOKIE,
        "extract": ["database", "username"],
        "sleep": 1,
        "timeout": 15,
        "max_chars": 50,
        "authorization_reference": AUTH,
    }
    request.update(overrides)
    return request


class TestValidateBaseUrl(unittest.TestCase):
    def test_allowed(self):
        self.assertEqual(
            moodle_sqli.validate_base_url(BASE_URL), BASE_URL)
        self.assertEqual(
            moodle_sqli.validate_base_url(BASE_URL + "/"), BASE_URL)

    def test_rejected(self):
        for bad in ("http://127.0.0.1:8080/moodle2",
                    "http://127.0.0.1:8081/moodle",
                    "http://127.0.0.1:8080/",
                    "https://127.0.0.1:8080/moodle",
                    "http://localhost:8080/moodle",
                    "http://contaia.site/moodle",
                    "http://127.0.0.1:8080/moodle?x=1",
                    "http://127.0.0.1:8080/moodle; rm -rf /",
                    "http://127.0.0.1:8080/moodle\n127.0.0.1",
                    "", None):
            with self.subTest(bad=bad):
                self.assertRaises(moodle_sqli.ValidationError,
                                  moodle_sqli.validate_base_url, bad)


class TestValidateTokens(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(moodle_sqli.validate_token(SESSKEY, "sesskey"), SESSKEY)
        self.assertEqual(moodle_sqli.validate_token(COOKIE, "session-cookie"), COOKIE)

    def test_rejected(self):
        for bad in ("", "a b", "a;b", "a\nb", "a/b", "a=b", "a:b",
                    "a" * 129, "ábc"):
            with self.subTest(bad=bad):
                self.assertRaises(moodle_sqli.ValidationError,
                                  moodle_sqli.validate_token, bad, "sesskey")


class TestValidateExtract(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(moodle_sqli.validate_extract(["database"]),
                         ["database"])
        self.assertEqual(moodle_sqli.validate_extract(["username", "database"]),
                         ["username", "database"])
        self.assertEqual(moodle_sqli.validate_extract(["DATABASE"]), ["database"])

    def test_password_rejected(self):
        with self.assertRaises(moodle_sqli.ValidationError) as ctx:
            moodle_sqli.validate_extract(["password"])
        self.assertIn("password", str(ctx.exception).lower())
        with self.assertRaises(moodle_sqli.ValidationError):
            moodle_sqli.validate_extract(["database", "password"])

    def test_rejected(self):
        for bad in ([], ["email"], ["username", "username"], "database", None):
            with self.subTest(bad=bad):
                self.assertRaises(moodle_sqli.ValidationError,
                                  moodle_sqli.validate_extract, bad)


class TestPayloads(unittest.TestCase):
    def test_detection_sort(self):
        self.assertEqual(moodle_sqli.build_detection_sort(3),
                         "fullname OR SLEEP(3)")

    def test_build_sort_database(self):
        self.assertEqual(
            moodle_sqli.build_sort("database", "mo", "o", 3),
            "fullname OR (database()) LIKE 'moo%' AND SLEEP(3)")

    def test_build_sort_username(self):
        self.assertEqual(
            moodle_sqli.build_sort("username", "", "a", 3),
            "fullname OR (SELECT username FROM mdl_user LIMIT 1 OFFSET 0) "
            "LIKE 'a%' AND SLEEP(3)")

    def test_quote_and_wildcard_escaping(self):
        sort = moodle_sqli.build_sort("username", "o'b", "%", 3)
        # The quote is doubled for the SQL literal; % is escaped for LIKE.
        self.assertIn("o''b\\%", sort)
        self.assertNotIn("o'b%", sort)

    def test_build_command(self):
        command = moodle_sqli.build_command(base_request(), dry_run=True)
        self.assertIn("--dry-run", command)
        self.assertIn("--confirm-written-authorization", command)
        self.assertIn("--authorization-reference", command)
        self.assertIn("moodle_sqli.py", " ".join(command))
        self.assertNotIn("password", " ".join(command))
        execute = moodle_sqli.build_command(base_request(), dry_run=False)
        self.assertEqual(execute, [a for a in command if a != "--dry-run"])
        self.assertNotEqual(moodle_sqli.command_hash(command),
                            moodle_sqli.command_hash(execute))

    def test_dry_run_payloads_do_not_leak_secrets(self):
        payloads = moodle_sqli.build_dry_run_payloads(BASE_URL, ["database"], 3)
        dumped = json.dumps(payloads)
        self.assertNotIn(SESSKEY, dumped)
        self.assertNotIn(COOKIE, dumped)
        self.assertIn("database", dumped)
        self.assertIn("SLEEP(3)", dumped)

    def test_auth_reference_validation(self):
        self.assertEqual(moodle_sqli.validate_auth_reference(AUTH), AUTH)
        for bad in ("", "a; rm -rf /", "--flag", "../etc/passwd", "a b"):
            with self.subTest(bad=bad):
                self.assertRaises(moodle_sqli.ValidationError,
                                  moodle_sqli.validate_auth_reference, bad)


class TestDryRunSendsNothing(unittest.TestCase):
    def test_main_dry_run_exit_zero_and_no_network(self):
        # The mock is not even started here: a dry-run must not need it.
        out = io.StringIO()
        with redirect_stdout(out):
            rc = moodle_sqli.main([
                "--base-url", BASE_URL,
                "--extract", "database", "username",
                "--dry-run",
            ])
        self.assertEqual(rc, 0)
        data = json.loads(out.getvalue())
        self.assertTrue(data["dry_run"])
        self.assertEqual(data["extract"], ["database", "username"])

    def test_main_without_authorization_refused(self):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = moodle_sqli.main([
                "--base-url", BASE_URL,
                "--sesskey", SESSKEY,
                "--session-cookie", COOKIE,
                "--extract", "database",
            ])
        self.assertEqual(rc, 2)
        self.assertIn("authorization", err.getvalue().lower())


# -- Mock Moodle -------------------------------------------------------
# Answers slow (1.2 s) only when the tested character matches the
# expected value; fast otherwise. Values are fake: database "moodle",
# first username "admin".

MOCK_VALUES = {"database": "moodle", "username": "admin"}


class MockMoodleHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests_seen = 0

    def log_message(self, *args):
        pass

    def do_POST(self):
        type(self).requests_seen += 1
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        slow = False
        try:
            payload = json.loads(raw.decode("utf-8"))
            sort = payload[0]["args"]["sort"]
        except (ValueError, KeyError, IndexError, TypeError):
            sort = ""
        if "LIKE" not in sort and "SLEEP(" in sort:
            slow = True  # detection probe
        else:
            column = "database" if "(database())" in sort else "username"
            match = re.search(r"LIKE '([^']*)%'", sort)
            if match:
                tested = match.group(1)
                expected = MOCK_VALUES[column]
                if expected.startswith(tested):
                    slow = True
        if slow:
            time.sleep(1.2)
        body = json.dumps([{"data": {"courses": []}}]).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestAgainstMock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.httpd = ThreadingHTTPServer(
                ("127.0.0.1", 8080), MockMoodleHandler)
        except OSError:
            raise unittest.SkipTest("puerto 8080 ocupado; mock no disponible")
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_full_extraction_against_mock(self):
        MockMoodleHandler.requests_seen = 0
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = moodle_sqli.main([
                    "--base-url", BASE_URL,
                    "--sesskey", SESSKEY,
                    "--session-cookie", COOKIE,
                    "--extract", "database", "username",
                    "--sleep", "1",
                    "--confirm-written-authorization",
                    "--authorization-reference", AUTH,
                    "--evidence-dir", tmp,
                ])
            self.assertEqual(rc, 0)
            data = json.loads(out.getvalue())
            self.assertTrue(data["vulnerable"])
            self.assertEqual(data["results"], MOCK_VALUES)
            self.assertGreater(data["requests_sent"], 0)
            self.assertEqual(data["requests_sent"],
                             MockMoodleHandler.requests_seen)
            # Evidence exists and never contains the cookie or sesskey.
            manifest = json.loads(
                open(os.path.join(data["evidence_dir"], "manifest.json"),
                     encoding="utf-8").read())
            dumped = json.dumps(manifest)
            self.assertNotIn(SESSKEY, dumped)
            self.assertNotIn(COOKIE, dumped)
            self.assertIn("sha256", dumped)

    def test_dry_run_sends_zero_requests_to_mock(self):
        before = MockMoodleHandler.requests_seen
        out = io.StringIO()
        with redirect_stdout(out):
            rc = moodle_sqli.main([
                "--base-url", BASE_URL,
                "--extract", "database",
                "--dry-run",
            ])
        self.assertEqual(rc, 0)
        self.assertEqual(MockMoodleHandler.requests_seen, before)


class TestServerMoodleValidation(unittest.TestCase):
    def test_validate_moodle_request_ok(self):
        req = server.validate_moodle_request(base_request())
        self.assertEqual(req["base_url"], BASE_URL)
        self.assertEqual(req["extract"], ["database", "username"])

    def test_validate_moodle_request_rejects_password(self):
        with self.assertRaises(server.ValidationError):
            server.validate_moodle_request(
                base_request(extract=["password"]))

    def test_validate_moodle_request_rejects_other_host(self):
        with self.assertRaises(server.ValidationError):
            server.validate_moodle_request(
                base_request(base_url="http://127.0.0.1:8080/moodle2"))

    def test_validate_moodle_request_auth_optional(self):
        # Sin referencia el dry-run es una medición del scope: la
        # petición queda con None y el comando no lleva el flag.
        # La ejecución real sí exige una referencia.
        req = server.validate_moodle_request(
            base_request(authorization_reference=""))
        self.assertIsNone(req["authorization_reference"])
        command = server.build_moodle_command(req, dry_run=True)
        self.assertNotIn("--authorization-reference", command)
        self.assertNotIn(None, command)
        req = server.validate_moodle_request(base_request())
        self.assertEqual(req["authorization_reference"], AUTH)
        with self.assertRaises(server.ValidationError):
            server.validate_moodle_request(
                base_request(authorization_reference=""), require_auth=True)


if __name__ == "__main__":
    unittest.main()
