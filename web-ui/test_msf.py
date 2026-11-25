"""Unit + live tests for the Metasploit panel (web-ui/msf/).

These tests never run Metasploit, msfrpcd, msfmcpd, pentestx.py or
any scan/exploit. They exercise the panel's own validation, the MCP
client and the server's /api/msf/* endpoints against a mock msfmcpd
(a small HTTP JSON-RPC server in this file) that imitates the
official doc: 16 tools, read-only always on, the four dangerous
tools gated by a flag, and the {"metadata": ..., "data": ...}
response envelope.

Run:  python3 -m unittest discover -s web-ui -p "test_msf.py" -v
(from the repository root, or: python3 web-ui/test_msf.py)
"""

import json
import os
import shutil
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import server  # noqa: E402
from msf import msf_client as msf  # noqa: E402


# -- mock msfmcpd -------------------------------------------------------

FAKE_MODULES = [
    {"type": "exploit", "name": "windows/smb/ms17_010_eternalblue",
     "description": "MS17-010 EternalBlue SMB RCE (mock)"},
    {"type": "auxiliary", "name": "scanner/smb/smb_version",
     "description": "SMB version scanner (mock)"},
    {"type": "exploit", "name": "multi/handler",
     "description": "Generic payload handler (mock)"},
]

FAKE_MODULE_INFO = {
    ("exploit", "windows/smb/ms17_010_eternalblue"): {
        "name": "windows/smb/ms17_010_eternalblue",
        "type": "exploit",
        "description": "MS17-010 EternalBlue SMB RCE (mock)",
        "options": [
            {"name": "RHOSTS", "required": True, "default": "",
             "description": "The target host(s)"},
            {"name": "RPORT", "required": False, "default": 445,
             "description": "The target port"},
            {"name": "PAYLOAD", "required": False,
             "default": "windows/meterpreter/reverse_tcp",
             "description": "The payload to use"},
            {"name": "LHOST", "required": False, "default": "",
             "description": "The listen address"},
            {"name": "LPORT", "required": False, "default": 4444,
             "description": "The listen port"},
        ],
    },
    ("auxiliary", "scanner/smb/smb_version"): {
        "name": "scanner/smb/smb_version",
        "type": "auxiliary",
        "description": "SMB version scanner (mock)",
        "options": [
            {"name": "RHOSTS", "required": True, "default": "",
             "description": "The target host(s)"},
            {"name": "RPORT", "required": False, "default": 445,
             "description": "The target port"},
        ],
    },
    ("exploit", "multi/handler"): {
        "name": "multi/handler",
        "type": "exploit",
        "description": "Generic payload handler (mock)",
        "options": [
            {"name": "PAYLOAD", "required": True, "default": "",
             "description": "The payload to handle"},
            {"name": "LHOST", "required": True, "default": "",
             "description": "The listen address"},
            {"name": "LPORT", "required": True, "default": 4444,
             "description": "The listen port"},
            {"name": "ExitOnSession", "required": False, "default": True,
             "description": "Exit after a session is created"},
        ],
    },
}

READ_ONLY_TOOLS = [
    "msf_search_modules", "msf_module_info", "msf_host_info",
    "msf_service_info", "msf_vulnerability_info", "msf_note_info",
    "msf_credential_info", "msf_loot_info", "msf_module_results",
    "msf_running_stats", "msf_session_list", "msf_session_read",
]
DANGEROUS_TOOLS = [
    "msf_module_execute", "msf_module_check",
    "msf_session_stop", "msf_session_write",
]


class MockMsfmcpdHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep test output readable
        pass

    def _send(self, status, payload, headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _tool_result(self, req_id, data, is_error=False):
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "content": [{"type": "text",
                         "text": json.dumps({"metadata": {"query_time": 0.01},
                                             "data": data})}],
            "isError": is_error}}

    def _tool_error(self, req_id, message):
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "content": [{"type": "text", "text": message}],
            "isError": True}}

    def do_POST(self):
        state = self.server.mock_state
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except ValueError:
            self._send(400, {"error": "bad json"})
            return
        method = payload.get("method")
        req_id = payload.get("id")
        if req_id is None:
            # Notification (e.g. notifications/initialized): 202, no body.
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "initialize":
            self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "msfmcpd-mock", "version": "0.1"},
            }}, headers={"Mcp-Session-Id": "mock-session"})
            return
        if method == "tools/list":
            tools = READ_ONLY_TOOLS + (
                DANGEROUS_TOOLS if state["dangerous"] else [])
            self._send(200, {"jsonrpc": "2.0", "id": req_id, "result": {
                "tools": [{"name": name, "description": name,
                           "inputSchema": {"type": "object"}}
                          for name in tools]}})
            return
        if method != "tools/call":
            self._send(200, {"jsonrpc": "2.0", "id": req_id, "error": {
                "code": -32601, "message": "method not found"}})
            return
        params = payload.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        state["call_log"].append((name, args))
        if name in DANGEROUS_TOOLS and not state["dangerous"]:
            self._send(200, self._tool_error(
                req_id, "dangerous actions are disabled: enable them "
                        "with --enable-dangerous-actions"))
            return
        self._dispatch_tool(req_id, name, args)

    def _dispatch_tool(self, req_id, name, args):
        state = self.server.mock_state
        if name == "msf_search_modules":
            query = (args.get("query") or "").lower()
            found = [m for m in FAKE_MODULES
                     if not query or query in
                     (m["name"] + " " + m["description"] + " "
                      + m["type"]).lower()]
            self._send(200, self._tool_result(req_id, {"modules": found}))
        elif name == "msf_module_info":
            info = FAKE_MODULE_INFO.get((args.get("type"), args.get("name")))
            if info is None:
                self._send(200, self._tool_error(
                    req_id, "module not found"))
            else:
                self._send(200, self._tool_result(req_id, info))
        elif name == "msf_module_execute":
            state["job_counter"] += 1
            uuid = "%024d" % state["job_counter"]
            job_id = state["job_counter"]
            options = args.get("options") or {}
            if args.get("name") == "multi/handler":
                state["handlers"].append({
                    "uuid": uuid, "job_id": job_id,
                    "options": options})
                state["jobs"][uuid] = {
                    "status": "completed",
                    "result": {"job_id": job_id}}
            else:
                state["jobs"][uuid] = {
                    "status": "completed",
                    "result": {"job_id": job_id}}
                if msf.is_reverse_payload(options):
                    rhosts = (options.get("RHOSTS") or "").split(",")
                    target = rhosts[0].strip() if rhosts else ""
                    state["sessions"]["1"] = {
                        "type": "meterpreter",
                        "tunnel_local": "127.0.0.1:%s" % options.get(
                            "LPORT", 4444),
                        "tunnel_peer": "%s:52341" % target,
                        "target_host": target,
                        "via_exploit": args.get("name"),
                        "via_payload": options.get("PAYLOAD"),
                    }
            self._send(200, self._tool_result(
                req_id, {"job_id": job_id, "uuid": uuid}))
        elif name == "msf_module_check":
            state["job_counter"] += 1
            uuid = "%024d" % state["job_counter"]
            state["jobs"][uuid] = {
                "status": "completed",
                "result": {"code": "Vulnerable"}}
            self._send(200, self._tool_result(
                req_id, {"job_id": state["job_counter"], "uuid": uuid}))
        elif name == "msf_module_results":
            data = state["jobs"].get(
                args.get("uuid"), {"status": "running"})
            self._send(200, self._tool_result(req_id, data))
        elif name == "msf_running_stats":
            self._send(200, self._tool_result(req_id, {
                "waiting": [], "running": [],
                "results": list(state["jobs"])}))
        elif name == "msf_session_list":
            self._send(200, self._tool_result(req_id, state["sessions"]))
        elif name == "msf_session_stop":
            sid = str(args.get("session_id"))
            if sid in state["sessions"]:
                del state["sessions"][sid]
                self._send(200, self._tool_result(
                    req_id, {"result": "success"}))
            else:
                self._send(200, self._tool_error(
                    req_id, "session not active"))
        elif name in ("msf_host_info", "msf_service_info",
                      "msf_vulnerability_info"):
            self._send(200, self._tool_result(req_id, {"items": []}))
        else:
            self._send(200, self._tool_error(
                req_id, "unknown tool %s" % name))


def start_mock(dangerous=True):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), MockMsfmcpdHandler)
    httpd.mock_state = {
        "dangerous": dangerous,
        "call_log": [],
        "jobs": {},
        "sessions": {},
        "handlers": [],
        "job_counter": 0,
    }
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def start_backend():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def http_json(base, method, path, body=None, timeout=60):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class TestMsfValidation(unittest.TestCase):
    def test_module_name_ok_and_bad(self):
        self.assertEqual(
            msf.validate_module_name("windows/smb/ms17_010_eternalblue"),
            "windows/smb/ms17_010_eternalblue")
        for bad in ("", "../etc/passwd", "/abs/path", "a b",
                    "a;b", "a|b", "x" * 129):
            with self.subTest(bad=bad):
                self.assertRaises(msf.ValidationError,
                                  msf.validate_module_name, bad)

    def test_module_type(self):
        self.assertEqual(msf.validate_module_type("exploit"), "exploit")
        with self.assertRaises(msf.ValidationError):
            msf.validate_module_type("pwn")
        with self.assertRaises(msf.ValidationError):
            msf.validate_module_type("exploit", ("auxiliary",))

    def test_rhosts_allowlist(self):
        ok = msf.validate_options({"RHOSTS": "contaia.site"})
        self.assertEqual(ok["RHOSTS"], "contaia.site")
        ok = msf.validate_options({"RHOSTS": "127.0.0.1, contaia.site"})
        self.assertEqual(ok["RHOSTS"], "127.0.0.1, contaia.site")
        for bad in ("example.com", "192.168.1.1", "10.0.0.5",
                    "127.0.0.2", "127.0.0.1/24", "file:/tmp/hosts",
                    "contaia.site; id", ""):
            with self.subTest(bad=bad):
                self.assertRaises(
                    msf.ValidationError, msf.validate_options,
                    {"RHOSTS": bad})

    def test_lhost_only_loopback(self):
        # El handler escucha en local y nada más: 0.0.0.0 y
        # cualquier otra IP están prohibidos.
        self.assertEqual(
            msf.validate_options({"LHOST": "127.0.0.1"})["LHOST"],
            "127.0.0.1")
        for bad in ("0.0.0.0", "192.168.1.10", "10.0.0.1",
                    "contaia.site", "8.8.8.8"):
            with self.subTest(bad=bad):
                self.assertRaises(
                    msf.ValidationError, msf.validate_options,
                    {"LHOST": bad})

    def test_ports(self):
        self.assertEqual(
            msf.validate_options({"RPORT": "445"})["RPORT"], 445)
        for bad in (0, 65536, -1, "abc", True):
            with self.subTest(bad=bad):
                self.assertRaises(
                    msf.ValidationError, msf.validate_options,
                    {"RPORT": bad})

    def test_reverse_defaults_and_handler_spec(self):
        plan = msf.validate_msf_plan({
            "type": "exploit",
            "name": "windows/smb/ms17_010_eternalblue",
            "action": "run",
            "options": {"RHOSTS": "127.0.0.1",
                        "PAYLOAD": "windows/meterpreter/reverse_tcp"},
        })
        self.assertTrue(plan["reverse"])
        # Sin LHOST/LPORT, el plan los pone explícitos y lo dice.
        self.assertEqual(plan["options"]["LHOST"], "127.0.0.1")
        self.assertEqual(plan["options"]["LPORT"], 4444)
        self.assertTrue(any("LHOST" in n for n in plan["notes"]))
        self.assertTrue(any("LPORT" in n for n in plan["notes"]))
        handler = plan["handler"]
        self.assertEqual(handler["type"], "exploit")
        self.assertEqual(handler["name"], "multi/handler")
        self.assertEqual(handler["options"]["PAYLOAD"],
                         "windows/meterpreter/reverse_tcp")
        self.assertEqual(handler["options"]["LHOST"], "127.0.0.1")
        self.assertEqual(handler["options"]["LPORT"], 4444)
        self.assertIs(handler["options"]["ExitOnSession"], False)

    def test_non_reverse_no_handler(self):
        plan = msf.validate_msf_plan({
            "type": "exploit",
            "name": "windows/smb/ms17_010_eternalblue",
            "action": "run",
            "options": {"RHOSTS": "127.0.0.1",
                        "PAYLOAD": "windows/meterpreter/bind_tcp"},
        })
        self.assertFalse(plan["reverse"])
        self.assertIsNone(plan["handler"])
        self.assertEqual(plan["notes"], [])

    def test_reverse_variants(self):
        for payload in ("linux/x64/meterpreter/reverse_tcp",
                        "windows/meterpreter/reverse_https",
                        "generic/shell_reverse_tcp"):
            with self.subTest(payload=payload):
                plan = msf.validate_msf_plan({
                    "type": "exploit", "name": "multi/handler",
                    "action": "run",
                    "options": {"PAYLOAD": payload}})
                self.assertTrue(plan["reverse"])
                self.assertIsNotNone(plan["handler"])

    def test_redact_options(self):
        redacted = msf.redact_options({
            "RHOSTS": "127.0.0.1",
            "SMBPass": "no-se-guarda",
            "API_KEY": "abc",
            "BEARER-TOKEN": "xyz",
            "LPORT": 4444,
        })
        self.assertEqual(redacted["RHOSTS"], "127.0.0.1")
        self.assertEqual(redacted["LPORT"], 4444)
        self.assertEqual(redacted["SMBPass"], "***")
        self.assertEqual(redacted["API_KEY"], "***")
        self.assertEqual(redacted["BEARER-TOKEN"], "***")

    def test_option_key_and_limits(self):
        for bad in ("a b", "a;b", "a|b", "a$b", "", "x" * 129):
            with self.subTest(bad=bad):
                self.assertRaises(
                    msf.ValidationError, msf.validate_options,
                    {bad: "1"})
        with self.assertRaises(msf.ValidationError):
            msf.validate_options({"OPT": ["lista"]})
        with self.assertRaises(msf.ValidationError):
            msf.validate_options({"OPT": {"anidado": 1}})
        with self.assertRaises(msf.ValidationError):
            msf.validate_options(
                {"K%02d" % i: "v" for i in range(101)})
        with self.assertRaises(msf.ValidationError):
            msf.validate_options({"OPT": "x" * (8 * 1024 + 1)})

    def test_validate_plan_actions(self):
        with self.assertRaises(msf.ValidationError):
            msf.validate_msf_plan({
                "type": "payload", "name": "windows/meterpreter/reverse_tcp",
                "action": "check", "options": {}})
        with self.assertRaises(msf.ValidationError):
            msf.validate_msf_plan({
                "type": "nop", "name": "x86/single_byte",
                "action": "run", "options": {}})
        plan = msf.validate_msf_plan({
            "type": "auxiliary", "name": "scanner/smb/smb_version",
            "action": "check", "options": {"RHOSTS": "contaia.site"}})
        self.assertEqual(plan["action"], "check")

    def test_session_id(self):
        self.assertEqual(msf.validate_session_id(3), 3)
        self.assertEqual(msf.validate_session_id("2"), 2)
        for bad in (0, -1, "abc", 1.5, True, None):
            with self.subTest(bad=bad):
                self.assertRaises(msf.ValidationError,
                                  msf.validate_session_id, bad)


class TestMsfEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._old_env = dict(os.environ)
        cls.mock = start_mock(dangerous=True)
        cls.mock_url = "http://127.0.0.1:%d/" % cls.mock.server_address[1]
        os.environ["MSF_MCP_URL"] = cls.mock_url
        cls.backend = start_backend()
        cls.base = "http://127.0.0.1:%d" % cls.backend.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.mock.shutdown()
        cls.mock.server_close()
        cls.backend.shutdown()
        cls.backend.server_close()
        shutil.rmtree(server.MSF_RUNS_DIR, ignore_errors=True)
        os.environ.clear()
        os.environ.update(cls._old_env)

    def setUp(self):
        server.STATE.set_msf_plan(None)
        with server.STATE.lock:
            server.STATE.msf_handlers.clear()
        state = self.mock.mock_state
        state["call_log"].clear()
        state["jobs"].clear()
        state["sessions"].clear()
        state["handlers"].clear()
        state["job_counter"] = 0
        state["dangerous"] = True

    def _plan(self, action="run", payload="windows/meterpreter/reverse_tcp",
              target="127.0.0.1"):
        status, data = http_json(self.base, "POST", "/api/msf/plan", {
            "type": "exploit",
            "name": "windows/smb/ms17_010_eternalblue",
            "action": action,
            "options": {"RHOSTS": target, "PAYLOAD": payload},
        })
        self.assertEqual(status, 200, data)
        return data

    def _execute_calls(self):
        return [c for c in self.mock.mock_state["call_log"]
                if c[0] == "msf_module_execute"]

    def test_status_disconnected(self):
        os.environ["MSF_MCP_URL"] = "http://127.0.0.1:1/"
        try:
            status, data = http_json(self.base, "GET", "/api/msf/status")
        finally:
            os.environ["MSF_MCP_URL"] = self.mock_url
        self.assertEqual(status, 200)
        self.assertFalse(data["connected"])
        self.assertIn("msfmcpd", data["error"])

    def test_status_connected_dangerous(self):
        status, data = http_json(self.base, "GET", "/api/msf/status")
        self.assertEqual(status, 200, data)
        self.assertTrue(data["connected"])
        self.assertTrue(data["dangerous_actions"])
        self.assertIn("msf_module_execute", data["tools"])
        self.assertIn("msf_search_modules", data["tools"])

    def test_status_dangerous_disabled(self):
        self.mock.mock_state["dangerous"] = False
        status, data = http_json(self.base, "GET", "/api/msf/status")
        self.assertEqual(status, 200, data)
        self.assertTrue(data["connected"])
        self.assertFalse(data["dangerous_actions"])
        self.assertNotIn("msf_module_execute", data["tools"])

    def test_search_returns_mock_modules(self):
        status, data = http_json(self.base, "POST", "/api/msf/search", {
            "query": "smb"})
        self.assertEqual(status, 200, data)
        self.assertTrue(data["connected"])
        names = [m["name"] for m in data["modules"]]
        self.assertIn("windows/smb/ms17_010_eternalblue", names)
        self.assertIn("scanner/smb/smb_version", names)

    def test_modules_type_filter(self):
        status, data = http_json(
            self.base, "GET", "/api/msf/modules?type=auxiliary")
        self.assertEqual(status, 200, data)
        self.assertEqual(
            [m["name"] for m in data["modules"]],
            ["scanner/smb/smb_version"])

    def test_plan_reverse_returns_handler(self):
        data = self._plan()
        plan = data["plan"]
        self.assertTrue(plan["reverse"])
        self.assertIsNotNone(plan["handler"])
        self.assertEqual(plan["handler"]["name"], "multi/handler")
        self.assertEqual(plan["handler"]["options"]["LHOST"], "127.0.0.1")
        self.assertIn("LHOST", " ".join(plan["notes"]))
        self.assertIn("windows/smb/ms17_010_eternalblue",
                      data["summary"])
        self.assertIn("multi/handler", data["summary"])

    def test_plan_bad_target_400(self):
        status, data = http_json(self.base, "POST", "/api/msf/plan", {
            "type": "exploit",
            "name": "windows/smb/ms17_010_eternalblue",
            "action": "run",
            "options": {"RHOSTS": "example.com",
                        "PAYLOAD": "windows/meterpreter/reverse_tcp"},
        })
        self.assertEqual(status, 400, data)

    def test_check_without_checkbox_409(self):
        self._plan(action="check")
        status, data = http_json(self.base, "POST", "/api/msf/check", {
            "confirm": True, "confirm_written_authorization": False})
        self.assertEqual(status, 409, data)
        self.assertEqual(
            [c for c in self.mock.mock_state["call_log"]
             if c[0] == "msf_module_check"], [])

    def test_check_with_checkbox_200(self):
        self._plan(action="check")
        status, data = http_json(self.base, "POST", "/api/msf/check", {
            "confirm": True, "confirm_written_authorization": True})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["result"]["result"]["code"], "Vulnerable")
        self.assertIsNone(data["handler"])

    def test_run_reverse_with_checkbox(self):
        self._plan(action="run")
        status, data = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["status"], "completed")
        # El handler arranca ANTES que el exploit, por la misma
        # conexión MCP, y la sesión entrante queda vinculada.
        calls = self._execute_calls()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1]["name"], "multi/handler")
        self.assertEqual(calls[0][1]["options"]["LHOST"], "127.0.0.1")
        self.assertEqual(calls[0][1]["options"]["LPORT"], 4444)
        self.assertIs(calls[0][1]["options"]["ExitOnSession"], False)
        self.assertEqual(
            calls[1][1]["name"], "windows/smb/ms17_010_eternalblue")
        self.assertIsNotNone(data["handler"])
        self.assertEqual(data["handler"]["name"], "multi/handler")
        self.assertEqual(data["sessions_linked"], [1])
        # Evidencia en workspace/msf_runs/, sin secretos.
        manifest = (server.MSF_RUNS_DIR / data["run_id"]
                    / "manifest.json")
        self.assertTrue(manifest.is_file())
        record = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(record["handler"]["LHOST"], "127.0.0.1")
        self.assertEqual(record["sessions_linked"], [1])
        self.assertTrue(record["confirm_written_authorization"])

    def test_run_reverse_second_time_reuses_handler(self):
        self._plan(action="run")
        http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        self._plan(action="run")
        status, data = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        self.assertEqual(status, 200, data)
        self.assertTrue(data["handler"]["reused"])
        # Solo se arrancó un handler en el mock, no dos.
        handlers = [c for c in self._execute_calls()
                    if c[1]["name"] == "multi/handler"]
        self.assertEqual(len(handlers), 1)

    def test_run_ids_unique_same_second(self):
        # Dos ejecuciones seguidas no deben pisar el mismo
        # manifiesto de evidencia aunque caigan en el mismo segundo.
        self._plan(action="run")
        _, d1 = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        self._plan(action="run")
        _, d2 = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        self.assertNotEqual(d1["run_id"], d2["run_id"])
        self.assertTrue((server.MSF_RUNS_DIR / d1["run_id"]
                         / "manifest.json").is_file())
        self.assertTrue((server.MSF_RUNS_DIR / d2["run_id"]
                         / "manifest.json").is_file())

    def test_run_without_checkbox_409(self):
        self._plan(action="run")
        status, data = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": False})
        self.assertEqual(status, 409, data)
        self.assertEqual(self._execute_calls(), [])

    def test_run_without_plan_409(self):
        status, data = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        self.assertEqual(status, 409, data)

    def test_run_bad_target_409(self):
        # Un plan aprobado que ya no pasa la allowlist (p. ej.
        # manipulado) se rechaza en /run con 409, no se ejecuta.
        server.STATE.set_msf_plan({
            "type": "exploit",
            "name": "windows/smb/ms17_010_eternalblue",
            "action": "run",
            "options": {"RHOSTS": "example.com",
                        "PAYLOAD": "windows/meterpreter/reverse_tcp"},
            "options_redacted": {"RHOSTS": "example.com"},
            "reverse": True,
            "handler": None,
            "notes": [],
        })
        status, data = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        self.assertEqual(status, 409, data)
        self.assertEqual(self._execute_calls(), [])

    def test_run_dangerous_disabled_409(self):
        self.mock.mock_state["dangerous"] = False
        self._plan(action="run")
        status, data = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        self.assertEqual(status, 409, data)
        self.assertIn("--enable-dangerous-actions", data["error"])
        self.assertEqual(self._execute_calls(), [])

    def test_bind_payload_no_handler(self):
        self._plan(action="run", payload="windows/meterpreter/bind_tcp")
        status, data = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        self.assertEqual(status, 200, data)
        self.assertIsNone(data["handler"])
        self.assertEqual(
            [c for c in self._execute_calls()
             if c[1]["name"] == "multi/handler"], [])

    def test_sessions_and_stop(self):
        self._plan(action="run")
        http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True})
        status, data = http_json(self.base, "GET", "/api/msf/sessions")
        self.assertEqual(status, 200, data)
        self.assertIn("1", data["sessions"])
        self.assertEqual(
            data["sessions"]["1"]["via_exploit"],
            "windows/smb/ms17_010_eternalblue")
        # Sin casilla no se detiene.
        status, data = http_json(
            self.base, "POST", "/api/msf/session/stop", {
                "confirm": True,
                "confirm_written_authorization": False,
                "session_id": 1})
        self.assertEqual(status, 409, data)
        status, data = http_json(
            self.base, "POST", "/api/msf/session/stop", {
                "confirm": True,
                "confirm_written_authorization": True,
                "session_id": 1})
        self.assertEqual(status, 200, data)
        status, data = http_json(self.base, "GET", "/api/msf/sessions")
        self.assertNotIn("1", data["sessions"])

    def test_token_never_in_manifest(self):
        self._plan(action="run")
        status, data = http_json(self.base, "POST", "/api/msf/run", {
            "confirm": True, "confirm_written_authorization": True,
            "mcp_token": "SECRET-TOKEN-123"})
        self.assertEqual(status, 200, data)
        manifest = (server.MSF_RUNS_DIR / data["run_id"]
                    / "manifest.json")
        self.assertNotIn("SECRET-TOKEN-123",
                         manifest.read_text(encoding="utf-8"))

    def test_result_poll(self):
        self._plan(action="check")
        status, data = http_json(self.base, "POST", "/api/msf/check", {
            "confirm": True, "confirm_written_authorization": True})
        self.assertEqual(status, 200, data)
        # El resultado del check ya viene en la respuesta; el
        # endpoint de polling devuelve lo mismo por uuid (el
        # primer job del mock es 000000000000000000000001).
        status, polled = http_json(
            self.base, "GET", "/api/msf/result?uuid=%024d" % 1)
        self.assertEqual(status, 200, polled)
        self.assertEqual(polled["data"]["status"], "completed")
        self.assertEqual(polled["data"]["result"]["code"], "Vulnerable")


if __name__ == "__main__":
    unittest.main()
