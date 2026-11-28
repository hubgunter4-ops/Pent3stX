"""Unit tests for web-ui/server.py validation and API-only routes.

These tests never call pentestx.py, nmap, ZAP or any scanner. They exercise
validation, command-building functions, and local HTTP route behavior.

Run:  python3 -m unittest discover -s web-ui -p "test_server.py" -v
(from the repository root, or: python3 web-ui/test_server.py)
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import server  # noqa: E402


def base_plan(**overrides):
    plan = {
        "target": "contaia.site",
        "scope": "passive",
        "actions": ["passive", "correlate", "report"],
        "pipeline_profile": "with_owasp",
        "confirm_written_authorization": True,
    }
    plan.update(overrides)
    return plan


class TestValidateTarget(unittest.TestCase):
    def test_allowed(self):
        self.assertEqual(server.validate_target("contaia.site"), "contaia.site")
        self.assertEqual(server.validate_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(server.validate_target("https://contaia.site"), "https://contaia.site")
        self.assertEqual(server.validate_target("http://contaia.site:8080"), "http://contaia.site:8080")

    def test_rejected_hosts(self):
        for bad in ("example.com", "google.com", "192.168.1.1", "10.0.0.5",
                    "172.16.0.1", "8.8.8.8", "169.254.169.254", "0.0.0.0",
                    "224.0.0.1", "127.0.0.2", "localhost", ""):
            with self.subTest(bad=bad):
                self.assertRaises(server.ValidationError, server.validate_target, bad)

    def test_rejected_shapes(self):
        for bad in ("127.0.0.1/24", "10.10.50.0/24", "contaia.site/evil",
                    "contaia.site --dry-run", "contaia.site; rm -rf /",
                    "contaia.site|cat /etc/passwd", "contaia.site$(id)",
                    "-target", "contaia.site ", "contaia.site\n127.0.0.1"):
            with self.subTest(bad=bad):
                self.assertRaises(server.ValidationError, server.validate_target, bad)


class TestValidatePlan(unittest.TestCase):
    def test_ok(self):
        plan = server.validate_plan(base_plan())
        self.assertEqual(plan["target"], "contaia.site")
        self.assertEqual(plan["pipeline_profile"], "with_owasp")

    def test_authorization_is_a_checkbox(self):
        # La autorización es una casilla por ejecución, no un texto:
        # sin marcarla el plan es una medición del scope y dice
        # explícitamente "sin autorización confirmada"; marcada,
        # dice "autorización confirmada por casilla, sin referencia
        # en la interfaz". Nunca se inventa una referencia.
        for confirmed in (None, False):
            plan = server.validate_plan(
                base_plan(confirm_written_authorization=confirmed))
            self.assertIs(plan["confirm_written_authorization"], False)
            self.assertEqual(plan["authorization_note"],
                             "sin autorización confirmada")
        plan = server.validate_plan(base_plan())
        self.assertIs(plan["confirm_written_authorization"], True)
        self.assertEqual(
            plan["authorization_note"],
            "autorización confirmada por casilla, sin referencia "
            "en la interfaz")

    def test_bad_action(self):
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(actions=["passive", "exploit"]))
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(actions=["tool"]))
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(actions=[]))

    def test_bad_pipeline(self):
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(pipeline_profile="full"))
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(pipeline_profile="custom"))

    def test_active_needs_active_scope(self):
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(scope="passive", actions=["active"]))
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(scope="passive", pipeline_profile="full_web"))
        ok = server.validate_plan(base_plan(
            scope="active", actions=["active"], pipeline_profile="full_web"))
        self.assertEqual(ok["scope"], "active")

    def test_bad_scope(self):
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(scope="intrusive"))


class TestBuildCommand(unittest.TestCase):
    def test_exact_dry_run_command(self):
        plan = server.validate_plan(base_plan())
        command = server.build_command(plan, dry_run=True)
        self.assertIn("--dry-run", command)
        self.assertIn("--confirm-written-authorization", command)
        # La interfaz ya no escribe ninguna referencia: el comando
        # nunca lleva --authorization-reference (la CLI la toma de
        # scope.yaml) y nunca inventa una.
        self.assertNotIn("--authorization-reference", command)
        self.assertIn("contaia.site", command)
        self.assertNotIn("--install-tools", command)
        # Fixed argument list, no shell metacharacters anywhere.
        self.assertTrue(all(isinstance(a, str) for a in command))
        self.assertTrue(all(";" not in a and "|" not in a and "$" not in a for a in command))
        # The execute command is the dry-run command minus --dry-run.
        execute = server.build_command(plan, dry_run=False)
        self.assertEqual(execute, [a for a in command if a != "--dry-run"])
        self.assertNotEqual(server.command_hash(command), server.command_hash(execute))

    def test_command_without_checkbox(self):
        # Plan sin la casilla marcada (medición del scope): el
        # comando es el mismo (el flag --confirm-written-authorization
        # es parte fija del comando que se previsualiza) y sigue sin
        # llevar --authorization-reference.
        plan = server.validate_plan(
            base_plan(confirm_written_authorization=False))
        command = server.build_command(plan, dry_run=True)
        self.assertIn("--dry-run", command)
        self.assertIn("--confirm-written-authorization", command)
        self.assertNotIn("--authorization-reference", command)
        self.assertNotIn(None, command)
        execute = server.build_command(plan, dry_run=False)
        self.assertEqual(execute, [a for a in command if a != "--dry-run"])

    def test_confirmation_validation(self):
        # La casilla es un booleano: ausente equivale a sin marcar.
        self.assertIs(server.validate_confirmation(True), True)
        self.assertIs(server.validate_confirmation(False), False)
        self.assertIs(server.validate_confirmation(None), False)
        for bad in ("sí", "yes", 1, 0, ["true"]):
            with self.subTest(bad=bad):
                self.assertRaises(server.ValidationError,
                                  server.validate_confirmation, bad)

    def test_scope_yaml_reference_available(self):
        # La CLI toma su referencia de scope.yaml: el servidor
        # replica esa regla (misma lista de placeholders) para
        # decidir si la ejecución real puede pasar.
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "no-existe.yaml"
            self.assertFalse(
                server.scope_yaml_reference_available(missing))
            usable = Path(tmp) / "scope.yaml"
            usable.write_text(
                "targets: [contaia.site]\n"
                "authorization_reference: docs/AUTORIZACION-contaia.md\n",
                encoding="utf-8")
            self.assertTrue(server.scope_yaml_reference_available(usable))
            for placeholder in ("", "pendiente", "ejemplo", "example"):
                usable.write_text(
                    "authorization_reference: %s\n" % placeholder,
                    encoding="utf-8")
                self.assertFalse(
                    server.scope_yaml_reference_available(usable))
            for non_string in ("null", "~", "false", "123"):
                usable.write_text(
                    "authorization_reference: %s\n" % non_string,
                    encoding="utf-8")
                self.assertFalse(
                    server.scope_yaml_reference_available(usable))
            usable.write_text("targets: [contaia.site]\n",
                              encoding="utf-8")
            self.assertFalse(server.scope_yaml_reference_available(usable))
            usable.write_text("authorization_reference: [unclosed\n",
                              encoding="utf-8")
            self.assertFalse(server.scope_yaml_reference_available(usable))


class TestSessionName(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(server.validate_session_name("2026-11-25T01-00-00"), "2026-11-25T01-00-00")

    def test_rejected(self):
        for bad in ("../etc", "/etc/passwd", "a/b", "a b", "..", ""):
            with self.subTest(bad=bad):
                self.assertRaises(server.ValidationError, server.validate_session_name, bad)


class TestSessionSummary(unittest.TestCase):
    def test_list_sessions_exposes_only_validated_display_metadata(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "2026-11-27T20-00-00"
            session.mkdir()
            (session / "execution_manifest.json").write_text(json.dumps({
                "target": "127.0.0.1",
                "status": "completed",
                "timestamp_utc": "2026-11-28T02:00:00+00:00",
                "written_authorization_confirmed": True,
            }), encoding="utf-8")
            with mock.patch.object(server, "SESSIONS_DIR", root):
                sessions = server.list_sessions()
            self.assertEqual(sessions, [{
                "name": session.name,
                "manifest": True,
                "findings": False,
                "target": "127.0.0.1",
                "status": "completed",
                "created_at": "2026-11-28T02:00:00+00:00",
            }])


class TestClientApprovalIsolation(unittest.TestCase):
    def test_approvals_and_plans_do_not_cross_client_ids(self):
        state = server.State()
        first = "1" * 32
        second = "2" * 32
        state.set_pending_plan({"target": "127.0.0.1"}, first)
        state.set_dry_run({"target": "127.0.0.1"}, ["dry-run"], first)
        state.set_moodle_dry_run({"sesskey": "secret"}, ["moodle"], first)
        state.set_engine_plan({"goal": "local"}, None, first)
        state.set_msf_plan({"module": "allowlisted"}, first)

        self.assertIsNotNone(state.get_pending_plan(first))
        self.assertIsNotNone(state.get_dry_run(first))
        self.assertIsNotNone(state.get_moodle_dry_run(first))
        self.assertIsNotNone(state.get_engine_plan(first))
        self.assertIsNotNone(state.get_msf_plan(first))
        self.assertIsNone(state.get_pending_plan(second))
        self.assertIsNone(state.get_dry_run(second))
        self.assertIsNone(state.get_moodle_dry_run(second))
        self.assertIsNone(state.get_engine_plan(second))
        self.assertIsNone(state.get_msf_plan(second))


class TestOwnedSubprocessStop(unittest.TestCase):
    def test_stop_during_reservation_is_remembered_and_owner_scoped(self):
        class Process:
            def __init__(self):
                self.terminated = False

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                return 0

            def kill(self):
                self.terminated = True

        state = server.State()
        owner = "1" * 32
        other = "2" * 32
        self.assertTrue(state.reserve_process(owner))
        self.assertFalse(state.stop_process(other))
        self.assertTrue(state.stop_process(owner))
        process = Process()
        self.assertTrue(state.set_process(process, owner))
        process.terminate()
        self.assertTrue(process.terminated)
        state.clear_process(process, owner)
        self.assertFalse(state.stop_process(owner))


class TestMetasploitBearerHeader(unittest.TestCase):
    def test_bearer_token_is_parsed_and_malformed_headers_rejected(self):
        from types import SimpleNamespace
        handler = SimpleNamespace(headers={"Authorization": "Bearer local-token"})
        self.assertEqual(server.Handler._msf_token_from_header(handler), "local-token")
        for value in ("Basic local-token", "Bearer", "Bearer token with-space"):
            with self.subTest(value=value):
                handler.headers = {"Authorization": value}
                with self.assertRaises(server.ValidationError):
                    server.Handler._msf_token_from_header(handler)


class TestApiOnlyHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import threading
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = "http://127.0.0.1:%d" % cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def _get(self, path):
        import urllib.error
        import urllib.request
        try:
            response = urllib.request.urlopen(self.base_url + path, timeout=2)
        except urllib.error.HTTPError as error:
            return error.code, error.headers.get("Content-Type"), error.read()
        with response:
            return response.status, response.headers.get("Content-Type"), response.read()

    def test_root_does_not_serve_ui(self):
        status, content_type, body = self._get("/")
        self.assertEqual(status, 404)
        self.assertTrue(content_type.startswith("application/json"))
        self.assertNotIn(b"<html", body.lower())

    def test_unknown_static_path_is_404(self):
        status, content_type, body = self._get("/not-a-static-file.js")
        self.assertEqual(status, 404)
        self.assertTrue(content_type.startswith("application/json"))
        self.assertNotIn(b"<html", body.lower())

    def test_api_status_remains_available(self):
        import json
        status, content_type, body = self._get("/api/status")
        self.assertEqual(status, 200)
        self.assertTrue(content_type.startswith("application/json"))
        self.assertEqual(json.loads(body)["backend"], "ok")


if __name__ == "__main__":
    unittest.main()
