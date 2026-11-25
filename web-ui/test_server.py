"""Unit tests for web-ui/server.py validation only.

These tests never call pentestx.py, nmap, ZAP or any scanner. They only
exercise the server's own validation and command-building functions.

Run:  python3 -m unittest discover -s web-ui -p "test_server.py" -v
(from the repository root, or: python3 web-ui/test_server.py)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import server  # noqa: E402


def base_plan(**overrides):
    plan = {
        "target": "contaia.site",
        "scope": "passive",
        "actions": ["passive", "correlate", "report"],
        "pipeline_profile": "with_owasp",
        "authorization_reference": "docs/AUTORIZACION-contaia.md",
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

    def test_missing_authorization(self):
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(authorization_reference=""))
        with self.assertRaises(server.ValidationError):
            server.validate_plan(base_plan(authorization_reference=None))

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
        self.assertIn("--authorization-reference", command)
        self.assertIn("contaia.site", command)
        self.assertNotIn("--install-tools", command)
        # Fixed argument list, no shell metacharacters anywhere.
        self.assertTrue(all(isinstance(a, str) for a in command))
        self.assertTrue(all(";" not in a and "|" not in a and "$" not in a for a in command))
        # The execute command is the dry-run command minus --dry-run.
        execute = server.build_command(plan, dry_run=False)
        self.assertEqual(execute, [a for a in command if a != "--dry-run"])
        self.assertNotEqual(server.command_hash(command), server.command_hash(execute))

    def test_auth_reference_validation(self):
        self.assertEqual(
            server.validate_auth_reference("docs/AUTORIZACION-contaia.md"),
            "docs/AUTORIZACION-contaia.md")
        for bad in ("", "a; rm -rf /", "--flag", "../etc/passwd", "a b"):
            with self.subTest(bad=bad):
                self.assertRaises(server.ValidationError, server.validate_auth_reference, bad)


class TestSessionName(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(server.validate_session_name("2026-11-25T01-00-00"), "2026-11-25T01-00-00")

    def test_rejected(self):
        for bad in ("../etc", "/etc/passwd", "a/b", "a b", "..", ""):
            with self.subTest(bad=bad):
                self.assertRaises(server.ValidationError, server.validate_session_name, bad)


if __name__ == "__main__":
    unittest.main()
