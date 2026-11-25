"""Pent3stX Workbench — local backend (functional, controlled execution).

Serves the web-ui (Design Option 1) on 127.0.0.1 only and lets it call
the real ``pentestx.py`` CLI under the same guardrails as the CLI itself:

* target allowlist, checked by syntax only: exactly ``contaia.site``
  and ``127.0.0.1`` (private networks, 169.254.169.254, 0.0.0.0/0,
  networks broader than /24, multicast and any other loopback are
  rejected);
* ``--authorization-reference`` is mandatory and non-empty;
* only allowlisted actions and controlled pipelines
  (standard / with_intrusive / with_owasp / full_web);
* active actions require ``--scope active``;
* every execution requires a prior dry-run of the EXACT same command:
  ``/api/plan`` runs ``pentestx.py --dry-run`` and stores the command
  hash; ``/api/execute`` refuses (409) without that exact dry-run;
* the CLI is always run with ``subprocess`` without a shell, from a
  fixed argument list — no arbitrary commands, no ``--install-tools``,
  no custom profiles, no file uploads to the server.

It also exposes the standalone Moodle SQLi tool in ``web-ui/tools/``
(``/api/tools/moodle-sqli/dry-run`` and
``/api/tools/moodle-sqli/run``), under the same dry-run-first rule:
the tool only ever talks to http://127.0.0.1:8080/moodle, never
extracts the password hash, and the session cookie / sesskey are
never written to disk or returned in API responses.

And the rule-based planning engine in ``web-ui/engine/``
(``/api/engine/goals``, ``/api/engine/plan`` and
``/api/engine/run``): given a goal and the current mapping, it
generates an ordered plan of steps without executing anything; the
plan is then run step by step, checking each step's preconditions
and dry-running its exact command first. See
``web-ui/engine/DESIGN.md``.

Run from the repository root::

    python3 web-ui/server.py

Then open http://127.0.0.1:8765/ — the server only listens on loopback,
so the interface is only reachable from this machine.

This file never scans, resolves or contacts a target by itself; it
only validates the request and hands the fixed command to pentestx.py.
"""

import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 8765

REPO_ROOT = Path(os.environ.get("PENTESTX_ROOT", Path(__file__).resolve().parent.parent))
WEB_UI_DIR = Path(__file__).resolve().parent
TOOLS_DIR = WEB_UI_DIR / "tools"
MOODLE_SQLI = TOOLS_DIR / "moodle_sqli.py"
ENGINE_DIR = WEB_UI_DIR / "engine"
ENGINE_MODULE = ENGINE_DIR / "engine.py"
PENTESTX = REPO_ROOT / "pentestx.py"
WORKSPACE_DIR = REPO_ROOT / "workspace"
SESSIONS_DIR = WORKSPACE_DIR / "pentestx_sessions"
ENGINE_RUNS_DIR = WORKSPACE_DIR / "engine_runs"

ALLOWED_TARGETS = ("contaia.site", "127.0.0.1")
ALLOWED_SCOPES = ("passive", "active")
ALLOWED_ACTIONS = (
    "passive", "active", "web", "ports", "vuln", "owasp_web",
    "vulnerability", "correlate", "report", "correlated",
    # "intrusive" es una acción válida de la CLI (ACTIVE_ACTIONS en
    # pentestx.py); la usa el goal full_assessment del motor.
    "intrusive",
)
# Acciones que exigen scope active; la CLI también las trata como
# activas (ACTIVE_ACTIONS en pentestx.py).
ACTIVE_ACTIONS = ("active", "intrusive")
ALLOWED_PIPELINES = ("standard", "with_intrusive", "with_owasp", "full_web")
# Pipelines whose steps include intrusive/active work.
PIPELINES_NEEDING_ACTIVE_SCOPE = ("with_intrusive", "full_web")

MAX_BODY_BYTES = 64 * 1024
DRY_RUN_TIMEOUT = 120
EXECUTE_TIMEOUT = 600
MAX_FINDINGS = 200

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._\-/]+$")
_SESSION_NAME = re.compile(r"^[A-Za-z0-9._-]+$")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".gif": "image/gif",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}


class ValidationError(ValueError):
    """A request failed a server-side guardrail check."""


def validate_target(target):
    """Return the canonical target, or raise ValidationError.

    Syntax only: no DNS resolution and no network contact. Only the
    exact allowlist ``contaia.site`` / ``127.0.0.1`` passes, with an
    optional http(s) scheme and port. Everything else — other hosts,
    IPs, CIDR ranges, paths, shell metacharacters — is rejected.
    """
    if not isinstance(target, str):
        raise ValidationError("target debe ser texto")
    if any(c.isspace() for c in target):
        raise ValidationError("target no válido")
    value = target.strip()
    if not value:
        raise ValidationError("target es obligatorio")
    if len(value) > 253:
        raise ValidationError("target no válido")
    if value.startswith("-") or ".." in value:
        raise ValidationError("target no válido")
    if not re.fullmatch(r"[A-Za-z0-9.\-:/]+", value):
        raise ValidationError("target no válido: caracteres no permitidos")
    host = value
    if "://" in value:
        scheme, rest = value.split("://", 1)
        if scheme not in ("http", "https") or not rest:
            raise ValidationError("target no válido: solo http(s) o host simple")
        host = rest.split("/", 1)[0]
        if not host or "/" in rest.strip("/"):
            raise ValidationError("target no válido: no se admiten rutas")
    elif "/" in value:
        raise ValidationError("target no válido: no se admiten redes CIDR ni rutas")
    host_only = host.split(":", 1)[0]
    if ":" in host:
        port = host.split(":", 1)[1]
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValidationError("target no válido: puerto no válido")
    if not host_only:
        raise ValidationError("target no válido")
    try:
        ip = ipaddress.ip_address(host_only)
    except ValueError:
        ip = None
    if ip is not None:
        if str(ip) != "127.0.0.1":
            raise ValidationError("target fuera del alcance permitido")
    elif host_only not in ALLOWED_TARGETS:
        raise ValidationError("target fuera del alcance permitido: solo contaia.site y 127.0.0.1")
    return value


def validate_auth_reference(ref):
    """Return the authorization reference, or raise ValidationError."""
    if not isinstance(ref, str):
        raise ValidationError("authorization_reference es obligatoria")
    value = ref.strip()
    if not value:
        raise ValidationError("authorization_reference es obligatoria")
    if len(value) > 200:
        raise ValidationError("authorization_reference demasiado larga")
    if value.startswith("-") or ".." in value.split("/"):
        raise ValidationError("authorization_reference no válida")
    if not _SAFE_TOKEN.fullmatch(value):
        raise ValidationError("authorization_reference no válida: caracteres no permitidos")
    return value


def validate_plan(payload):
    """Validate a /api/plan payload. Returns a clean plan dict."""
    if not isinstance(payload, dict):
        raise ValidationError("el cuerpo debe ser un objeto JSON")
    target = validate_target(payload.get("target"))
    scope = payload.get("scope")
    if scope not in ALLOWED_SCOPES:
        raise ValidationError("scope debe ser passive o active")
    actions = payload.get("actions")
    if not isinstance(actions, list) or not actions:
        raise ValidationError("actions debe ser una lista no vacía")
    if any(not isinstance(a, str) or a not in ALLOWED_ACTIONS for a in actions):
        raise ValidationError("acción no permitida: %s" % (actions,))
    if len(set(actions)) != len(actions):
        raise ValidationError("acciones duplicadas")
    if any(a in ACTIVE_ACTIONS for a in actions) and scope != "active":
        raise ValidationError("las acciones activas exigen scope active")
    pipeline = payload.get("pipeline_profile")
    if pipeline not in ALLOWED_PIPELINES:
        raise ValidationError("pipeline_profile no permitido")
    if pipeline in PIPELINES_NEEDING_ACTIVE_SCOPE and scope != "active":
        raise ValidationError("el pipeline %s exige scope active" % pipeline)
    auth_ref = validate_auth_reference(payload.get("authorization_reference"))
    return {
        "target": target,
        "scope": scope,
        "actions": list(actions),
        "pipeline_profile": pipeline,
        "authorization_reference": auth_ref,
    }


def build_command(plan, dry_run):
    """Build the exact, fixed CLI argument list for a validated plan."""
    command = [
        sys.executable,
        str(PENTESTX),
        "--target", plan["target"],
        "--scope", plan["scope"],
        "--action", *plan["actions"],
        "--pipeline-profile", plan["pipeline_profile"],
        "--confirm-written-authorization",
        "--authorization-reference", plan["authorization_reference"],
    ]
    if (REPO_ROOT / "scope.yaml").exists():
        command += ["--scope-file", "scope.yaml"]
    if dry_run:
        command.append("--dry-run")
    return command


def command_hash(command):
    return hashlib.sha256(json.dumps(command).encode("utf-8")).hexdigest()


def engine_plan_hash(plan):
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


# -- Moodle SQLi tool (web-ui/tools/moodle_sqli.py) -------------------
# Validation lives in the tool itself; the server loads it (by path,
# never from an installed package) so there is a single definition
# of what is allowed. The sesskey / cookie only ever live in server
# memory for the approved dry-run; they are never logged, never
# written to disk by this server, and never returned in a response.

def _load_moodle_tool():
    if not MOODLE_SQLI.is_file():
        raise ValidationError("moodle_sqli.py no encontrado en web-ui/tools/")
    spec = importlib.util.spec_from_file_location(
        "moodle_sqli_tool", MOODLE_SQLI)
    if spec is None or spec.loader is None:
        raise ValidationError("no se pudo cargar moodle_sqli.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_moodle_request(payload):
    """Validate a moodle-sqli request; returns a clean dict (in memory)."""
    if not isinstance(payload, dict):
        raise ValidationError("el cuerpo debe ser un objeto JSON")
    tool = _load_moodle_tool()
    try:
        base_url = tool.validate_base_url(payload.get("base_url"))
        sesskey = tool.validate_token(payload.get("sesskey"), "sesskey")
        session_cookie = tool.validate_token(
            payload.get("session_cookie"), "session-cookie")
        extract = tool.validate_extract(payload.get("extract"))
        sleep = tool.validate_number(payload.get("sleep", 3), "sleep", 1, 10)
        timeout = tool.validate_number(
            payload.get("timeout", 15), "timeout", 5, 60)
        max_chars = tool.validate_number(
            payload.get("max_chars", 50), "max-chars", 1, 50)
    except tool.ValidationError as exc:
        raise ValidationError(str(exc))
    auth_ref = validate_auth_reference(payload.get("authorization_reference"))
    return {
        "base_url": base_url,
        "sesskey": sesskey,
        "session_cookie": session_cookie,
        "extract": extract,
        "sleep": sleep,
        "timeout": timeout,
        "max_chars": max_chars,
        "authorization_reference": auth_ref,
    }


def build_moodle_command(request, dry_run):
    tool = _load_moodle_tool()
    return tool.build_command(request, dry_run)


def _parse_tool_json(text):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


# -- Planning engine (web-ui/engine/engine.py) ----------------------
# The planner itself is pure (no network, no disk): the server only
# feeds it the current mapping and, for the Moodle goal, the session
# the user provided. The sesskey / cookie only ever live in server
# memory for the approved plan; they are never logged, never written
# to disk by this server, and never returned in a response.

def _load_engine():
    if not ENGINE_MODULE.is_file():
        raise ValidationError("engine.py no encontrado en web-ui/engine/")
    spec = importlib.util.spec_from_file_location(
        "pentestx_engine", ENGINE_MODULE)
    if spec is None or spec.loader is None:
        raise ValidationError("no se pudo cargar engine.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _current_mapping():
    """Mapping the planner needs: installed tools + existing sessions."""
    return {
        "tools_available": {
            "nmap": shutil.which("nmap") is not None,
            "ffuf": shutil.which("ffuf") is not None,
            "sqlmap": shutil.which("sqlmap") is not None,
        },
        "sessions": [s["name"] for s in list_sessions()],
    }


def validate_engine_plan_request(payload):
    """Validate an /api/engine/plan payload; returns the approved plan.

    The Moodle session is optional at plan time: without sesskey +
    cookie the Moodle steps are generated as blocked (the plan says
    so) instead of failing the request. A wrong base_url, though, is
    a real error.
    """
    if not isinstance(payload, dict):
        raise ValidationError("el cuerpo debe ser un objeto JSON")
    engine = _load_engine()
    goal = payload.get("goal")
    if not isinstance(goal, str) or goal not in engine.GOALS:
        raise ValidationError(
            "goal no permitido: %s (goals: %s)"
            % (goal, ", ".join(sorted(engine.GOALS))))
    scope = payload.get("scope") or engine.GOALS[goal]["scope"]
    target = payload.get("target")
    auth_ref = validate_auth_reference(payload.get("authorization_reference"))
    moodle_payload = payload.get("moodle")
    moodle_request = None
    moodle_info = None
    if goal == "moodle_sqli_confirm":
        if isinstance(moodle_payload, dict) and moodle_payload:
            if (moodle_payload.get("base_url")
                    and moodle_payload.get("base_url")
                    != engine.MOODLE_BASE_URL):
                raise ValidationError(
                    "base-url no permitido: solo %s"
                    % engine.MOODLE_BASE_URL)
            try:
                moodle_request = validate_moodle_request(
                    dict(moodle_payload,
                         # extract por defecto: database + username
                         # (la UI del motor no lo pide; nunca password).
                         extract=moodle_payload.get("extract") or [
                             "database", "username"],
                         authorization_reference=auth_ref))
                moodle_info = {
                    "base_url": moodle_request["base_url"],
                    "sesskey_present": True,
                    "cookie_present": True,
                }
            except ValidationError as exc:
                # Missing sesskey/cookie: the plan is generated with
                # the Moodle steps blocked; anything else is an error.
                message = str(exc)
                if "sesskey" in message or "session-cookie" in message:
                    moodle_request = None
                    moodle_info = None
                else:
                    raise
    try:
        plan = engine.generate_plan(
            goal, target, scope, auth_ref,
            mapping=_current_mapping(), moodle=moodle_info)
    except engine.ValidationError as exc:
        raise ValidationError(str(exc))
    return {"plan": plan, "moodle_request": moodle_request}


def _redact_plan(plan):
    """A generated plan never contains secrets (the sample commands
    redact them), but round-trip it so nothing else leaks either."""
    return json.loads(json.dumps(plan, ensure_ascii=False))


def _save_engine_run(run_id, plan, step_results, status):
    """Evidence of an engine run: plan + per-step results, no secrets."""
    directory = ENGINE_RUNS_DIR / run_id
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "run_id": run_id,
        "goal": plan["goal"],
        "target": plan["target"],
        "scope": plan["scope"],
        "pipeline_profile": plan["pipeline_profile"],
        "authorization_reference": plan["authorization_reference"],
        "status": status,
        "plan": _redact_plan(plan),
        "steps": step_results,
    }
    (directory / "plan.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(directory)


def run_engine_plan(approved):
    """Run an approved engine plan step by step.

    Before each step, its preconditions are re-checked against the
    results so far (via engine.replan); a step that may not run is
    recorded as skipped/blocked with its reason, never executed.
    Each pentestx step dry-runs its exact command first, then
    executes it; each Moodle step does the same through the
    moodle-sqli endpoints' own flow.
    """
    import time as _time

    engine = _load_engine()
    plan = approved["plan"]
    moodle_request = approved.get("moodle_request")
    run_id = _time.strftime("%Y%m%dT%H%M%SZ", _time.gmtime())
    mapping = _current_mapping()
    results = {}
    step_results = []
    live_plan = json.loads(json.dumps(plan, ensure_ascii=False))
    stopped = False

    def context():
        return {
            "tools_available": mapping["tools_available"],
            "scope": plan["scope"],
            "moodle_session": moodle_request is not None,
            "results": results,
        }

    for step in live_plan["steps"]:
        step_id = step["id"]
        status = step.get("status")
        if status in ("skipped_missing_dependency", "blocked"):
            result = {
                "id": step_id, "action": step["action"],
                "tool": step["tool"], "status": status,
                "reason": step.get("blocked_reason", ""),
            }
            results[step_id] = result
            step_results.append(result)
            continue
        if stopped:
            result = {
                "id": step_id, "action": step["action"],
                "tool": step["tool"], "status": "skipped",
                "reason": "stopped: un paso anterior falló",
            }
            results[step_id] = result
            step_results.append(result)
            continue
        # Re-plan with what is known so far; a step whose
        # preconditions no longer hold is skipped, never executed.
        live_plan = engine.replan(live_plan, results, context())
        live_step = next(
            s for s in live_plan["steps"] if s["id"] == step_id)
        if live_step.get("status") != "pending":
            result = {
                "id": step_id, "action": step["action"],
                "tool": step["tool"],
                "status": live_step.get("status"),
                "reason": live_step.get("blocked_reason", ""),
            }
            results[step_id] = result
            step_results.append(result)
            continue
        if step["tool"] == "moodle_sqli":
            result = _run_engine_moodle_step(
                plan, step, moodle_request)
        else:
            result = _run_engine_pentestx_step(plan, step)
        results[step_id] = result
        step_results.append(result)
        if result["status"] == "failed" and step.get("on_fail") == "stop":
            stopped = True

    if stopped:
        status = "stopped"
    elif any(r["status"] in ("failed", "skipped", "blocked",
                             "skipped_missing_dependency")
             for r in step_results):
        status = "completed_with_warnings"
    else:
        status = "completed"
    evidence_dir = _save_engine_run(run_id, live_plan, step_results, status)
    return {
        "run_id": run_id,
        "goal": plan["goal"],
        "status": status,
        "evidence_dir": evidence_dir,
        "steps": step_results,
    }


def _truncate(text, limit=4000):
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "\n… (recortado)"


def _run_engine_pentestx_step(plan, step):
    """One pentestx step: dry-run of the exact command, then execute."""
    engine = _load_engine()
    dry = engine.build_pentestx_command(plan, step, dry_run=True)
    result = run_cli(dry, DRY_RUN_TIMEOUT)
    if result["exit_code"] != 0:
        return {
            "id": step["id"], "action": step["action"],
            "tool": "pentestx", "status": "failed",
            "exit_code": result["exit_code"],
            "session_dir": result.get("session_dir"),
            "stdout": _truncate(result["stdout"]),
            "stderr": _truncate(result["stderr"]),
            "reason": "dry-run rechazado por la CLI",
        }
    command = engine.build_pentestx_command(plan, step, dry_run=False)
    result = run_cli(command, EXECUTE_TIMEOUT)
    return {
        "id": step["id"], "action": step["action"],
        "tool": "pentestx",
        "status": "completed" if result["exit_code"] == 0 else "failed",
        "exit_code": result["exit_code"],
        "session_dir": result.get("session_dir"),
        "stdout": _truncate(result["stdout"]),
        "stderr": _truncate(result["stderr"]),
        "reason": "" if result["exit_code"] == 0
                else "la CLI terminó con exit %d" % result["exit_code"],
    }


def _run_engine_moodle_step(plan, step, moodle_request):
    """One Moodle step: dry-run, then run the tool (detect or extract).

    The dry-run and run commands are rebuilt from the approved
    request (in memory only); the plan's sample command is redacted
    and is never executed.
    """
    if step["id"] == "moodle_detect":
        request = dict(moodle_request, extract=["database"], max_chars=1)
    else:
        request = moodle_request
    dry = build_moodle_command(request, dry_run=True)
    result = _run_process(dry, 60)
    if result["exit_code"] != 0:
        return {
            "id": step["id"], "action": step["action"],
            "tool": "moodle_sqli", "status": "failed",
            "exit_code": result["exit_code"],
            "stdout": _truncate(result["stdout"]),
            "stderr": _truncate(result["stderr"]),
            "reason": "dry-run rechazado por la herramienta",
        }
    command = build_moodle_command(request, dry_run=False)
    result = _run_process(command, EXECUTE_TIMEOUT)
    data = _parse_tool_json(result["stdout"])
    vulnerable = (data or {}).get("vulnerable")
    status = "completed" if result["exit_code"] == 0 else "failed"
    if step["id"] == "moodle_detect" and status == "completed":
        # The detection only counts as completed if it actually
        # confirmed the vulnerability; otherwise the extract step
        # must not run (its precondition checks this).
        status = "completed" if vulnerable is True else "failed"
    return {
        "id": step["id"], "action": step["action"],
        "tool": "moodle_sqli", "status": status,
        "exit_code": result["exit_code"],
        "stdout": _truncate(result["stdout"]),
        "stderr": _truncate(result["stderr"]),
        "result": data,
        "reason": "" if status == "completed"
                else "la sonda no confirmó la vulnerabilidad"
                if step["id"] == "moodle_detect"
                else "la herramienta terminó con exit %d"
                % result["exit_code"],
    }


def validate_session_name(name):
    """Return a safe session directory name, or raise ValidationError."""
    if not isinstance(name, str) or not _SESSION_NAME.fullmatch(name) or name in (".", ".."):
        raise ValidationError("nombre de sesión no válido")
    return name


def list_sessions():
    """List real sessions under workspace/pentestx_sessions/."""
    sessions = []
    if not SESSIONS_DIR.is_dir():
        return sessions
    for entry in sorted(SESSIONS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not entry.is_dir():
            continue
        sessions.append({
            "name": entry.name,
            "manifest": (entry / "execution_manifest.json").exists(),
            "findings": (entry / "findings_db.json").exists(),
        })
    return sessions


def read_manifest(session_dir):
    path = session_dir / "execution_manifest.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def read_findings(session_name):
    """Read findings_db.json of one session, verbatim, capped at 200."""
    name = validate_session_name(session_name)
    path = (SESSIONS_DIR / name / "findings_db.json").resolve()
    if not str(path).startswith(str(SESSIONS_DIR.resolve())):
        raise ValidationError("nombre de sesión no válido")
    if not path.is_file():
        raise FileNotFoundError("la sesión no tiene findings_db.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        findings = [data]
    return findings[:MAX_FINDINGS]


class State:
    """Server-side state: the approved dry-run and the running process."""

    def __init__(self):
        self.lock = threading.Lock()
        self.dry_run = None  # {"hash": str, "plan": dict, "command": list}
        self.moodle_dry_run = None  # {"hash": str, "request": dict, "command": list}
        self.engine_plan = None  # {"hash": str, "plan": dict, "moodle_request": dict|None}
        self.process = None

    def set_dry_run(self, plan, command):
        with self.lock:
            self.dry_run = {"hash": command_hash(command), "plan": plan, "command": command}

    def get_dry_run(self):
        with self.lock:
            return self.dry_run

    def set_moodle_dry_run(self, request, command):
        with self.lock:
            self.moodle_dry_run = {
                "hash": command_hash(command),
                "request": request,
                "command": command,
            }

    def get_moodle_dry_run(self):
        with self.lock:
            return self.moodle_dry_run

    def set_engine_plan(self, plan, moodle_request):
        with self.lock:
            self.engine_plan = {
                "hash": engine_plan_hash(plan),
                "plan": plan,
                "moodle_request": moodle_request,
            }

    def get_engine_plan(self):
        with self.lock:
            return self.engine_plan

    def set_process(self, proc):
        with self.lock:
            self.process = proc

    def clear_process(self):
        with self.lock:
            self.process = None

    def stop_process(self):
        with self.lock:
            proc = self.process
        if proc is None:
            return False
        try:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        except (ProcessLookupError, PermissionError):
            pass
        return True


STATE = State()


def _run_process(command, timeout):
    """Run a fixed command without a shell; returns stdout/stderr/exit_code.

    The running process is tracked in STATE so /api/stop can kill it.
    """
    proc = subprocess.Popen(
        command,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        start_new_session=True,
    )
    STATE.set_process(proc)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        exit_code = 124
    finally:
        STATE.clear_process()
    return {"stdout": stdout or "", "stderr": stderr or "", "exit_code": exit_code}


def run_cli(command, timeout):
    """Run pentestx.py without a shell; returns stdout/stderr/exit_code."""
    before = {s["name"] for s in list_sessions()}
    result = _run_process(command, timeout)
    after = list_sessions()
    new_sessions = [s for s in after if s["name"] not in before]
    session_dir = new_sessions[0]["name"] if new_sessions else (after[0]["name"] if after else None)
    manifest = None
    if session_dir:
        manifest = read_manifest(SESSIONS_DIR / session_dir)
    return {
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "exit_code": result["exit_code"],
        "session_dir": session_dir,
        "manifest": manifest,
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep stdout for real run output only
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- helpers ------------------------------------------------------
    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValidationError("cuerpo vacío o demasiado grande")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ValidationError("cuerpo JSON no válido")
        return data

    # -- API ----------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/status":
                self._send_json(200, {
                    "backend": "ok",
                    "pentestx_present": PENTESTX.is_file(),
                    "repo_root": str(REPO_ROOT),
                })
            elif path == "/api/engine/goals":
                engine = _load_engine()
                self._send_json(200, {"goals": engine.list_goals()})
            elif path == "/api/sessions":
                self._send_json(200, {"sessions": list_sessions()})
            elif path == "/api/findings":
                name = parse_qs(parsed.query).get("session", [None])[0]
                if not name:
                    self._send_json(400, {"error": "falta el parámetro session"})
                    return
                try:
                    findings = read_findings(name)
                except FileNotFoundError:
                    self._send_json(404, {"error": "la sesión no tiene findings_db.json"})
                    return
                self._send_json(200, {"session": name, "findings": findings})
            elif path == "/" or path == "":
                self._serve_static("index.html")
            else:
                self._serve_static(path.lstrip("/"))
        except ValidationError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - report as JSON, never crash
            self._send_json(500, {"error": "error interno: %s" % exc})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/plan":
                payload = self._read_json()
                plan = validate_plan(payload)
                if not PENTESTX.is_file():
                    self._send_json(500, {"error": "pentestx.py no encontrado en la raíz del repo"})
                    return
                command = build_command(plan, dry_run=True)
                result = run_cli(command, DRY_RUN_TIMEOUT)
                if result["exit_code"] == 0:
                    # Only a successful dry-run approves the exact command.
                    STATE.set_dry_run(plan, command)
                self._send_json(200, {
                    "command_exact": command,
                    "command": " ".join(command),
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                    "exit_code": result["exit_code"],
                    "manifest": result["manifest"],
                    "session_dir": result["session_dir"],
                })
            elif path == "/api/execute":
                payload = self._read_json()
                if payload.get("confirm") is not True:
                    self._send_json(400, {"error": "falta confirm: true"})
                    return
                auth_ref = validate_auth_reference(payload.get("authorization_reference"))
                approved = STATE.get_dry_run()
                if approved is None:
                    self._send_json(409, {"error": "sin dry-run previo: ejecuta /api/plan primero"})
                    return
                if approved["plan"]["authorization_reference"] != auth_ref:
                    self._send_json(409, {"error": "la referencia de autorización no coincide con la del dry-run"})
                    return
                if not PENTESTX.is_file():
                    self._send_json(500, {"error": "pentestx.py no encontrado en la raíz del repo"})
                    return
                command = build_command(approved["plan"], dry_run=False)
                if command_hash(command) != command_hash(
                        build_command(approved["plan"], dry_run=True)[:-1]):
                    self._send_json(409, {"error": "el comando cambió tras el dry-run"})
                    return
                result = run_cli(command, EXECUTE_TIMEOUT)
                self._send_json(200, {
                    "command_exact": command,
                    "command": " ".join(command),
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                    "exit_code": result["exit_code"],
                    "session_dir": result["session_dir"],
                    "manifest": result["manifest"],
                })
            elif path == "/api/tools/moodle-sqli/dry-run":
                # Validates and shows the exact payloads; sends nothing.
                # The response never contains the sesskey or the cookie.
                payload = self._read_json()
                request = validate_moodle_request(payload)
                command = build_moodle_command(request, dry_run=True)
                result = _run_process(command, 60)
                if result["exit_code"] == 0:
                    STATE.set_moodle_dry_run(request, command)
                data = _parse_tool_json(result["stdout"])
                self._send_json(200, {
                    "dry_run": True,
                    "exit_code": result["exit_code"],
                    "stderr": result["stderr"],
                    "payloads": (data or {}).get("payloads"),
                    "base_url": request["base_url"],
                    "extract": request["extract"],
                })
            elif path == "/api/tools/moodle-sqli/run":
                payload = self._read_json()
                if payload.get("confirm") is not True:
                    self._send_json(400, {"error": "falta confirm: true"})
                    return
                auth_ref = validate_auth_reference(
                    payload.get("authorization_reference"))
                approved = STATE.get_moodle_dry_run()
                if approved is None:
                    self._send_json(409, {
                        "error": "sin dry-run previo: ejecuta "
                                 "/api/tools/moodle-sqli/dry-run primero"})
                    return
                if approved["request"]["authorization_reference"] != auth_ref:
                    self._send_json(409, {
                        "error": "la referencia de autorización no coincide "
                                 "con la del dry-run"})
                    return
                command = build_moodle_command(approved["request"], dry_run=False)
                if command_hash(command) != command_hash(
                        build_moodle_command(
                            approved["request"], dry_run=True)[:-1]):
                    self._send_json(409, {
                        "error": "el comando cambió tras el dry-run"})
                    return
                result = _run_process(command, EXECUTE_TIMEOUT)
                data = _parse_tool_json(result["stdout"])
                self._send_json(200, {
                    "exit_code": result["exit_code"],
                    "stderr": result["stderr"],
                    "result": data,
                })
            elif path == "/api/engine/plan":
                # Generates the plan only; executes nothing.
                payload = self._read_json()
                approved = validate_engine_plan_request(payload)
                plan = approved["plan"]
                STATE.set_engine_plan(plan, approved["moodle_request"])
                self._send_json(200, {
                    "plan": _redact_plan(plan),
                    "plan_hash": engine_plan_hash(plan),
                })
            elif path == "/api/engine/run":
                payload = self._read_json()
                if payload.get("confirm") is not True:
                    self._send_json(400, {"error": "falta confirm: true"})
                    return
                auth_ref = validate_auth_reference(
                    payload.get("authorization_reference"))
                approved = STATE.get_engine_plan()
                if approved is None:
                    self._send_json(409, {
                        "error": "sin plan aprobado: ejecuta "
                                 "/api/engine/plan primero"})
                    return
                if (approved["plan"]["authorization_reference"]
                        != auth_ref):
                    self._send_json(409, {
                        "error": "la referencia de autorización no coincide "
                                 "con la del plan aprobado"})
                    return
                if STATE.process is not None:
                    self._send_json(409, {
                        "error": "ya hay una ejecución en curso"})
                    return
                result = run_engine_plan(approved)
                self._send_json(200, result)
            elif path == "/api/stop":
                stopped = STATE.stop_process()
                self._send_json(200, {"stopped": stopped})
            else:
                self._send_json(404, {"error": "ruta no encontrada"})
        except ValidationError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - report as JSON, never crash
            self._send_json(500, {"error": "error interno: %s" % exc})

    # -- static files -------------------------------------------------
    def _serve_static(self, name):
        if name.endswith(".py") or "/." in ("/" + name) or name.startswith("."):
            self._send_json(404, {"error": "archivo no encontrado"})
            return
        target = (WEB_UI_DIR / name).resolve()
        if not str(target).startswith(str(WEB_UI_DIR.resolve())) or not target.is_file():
            self._send_json(404, {"error": "archivo no encontrado"})
            return
        ctype = CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    if not PENTESTX.is_file():
        print("AVISO: pentestx.py no encontrado en %s" % REPO_ROOT, file=sys.stderr)
        print("Arranca el servidor desde la raíz del repositorio clonado.", file=sys.stderr)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("Pent3stX Workbench backend en http://%s:%d/ (solo local)" % (HOST, PORT))
    print("Raíz del repo: %s" % REPO_ROOT)
    print("Pulsa Ctrl+C para detenerlo.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDeteniendo el backend.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
