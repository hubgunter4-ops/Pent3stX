"""Metasploit panel client (web-ui/msf/msf_client.py) — stdlib only.

Talks MCP JSON-RPC 2.0 over HTTP to the official Metasploit MCP
server ``msfmcpd`` (docs.metasploit.com: "How to use Metasploit MCP
Server"). ``msfmcpd`` exposes 16 tools:

* read-only (always enabled): msf_search_modules, msf_module_info,
  msf_host_info, msf_service_info, msf_vulnerability_info,
  msf_note_info, msf_credential_info, msf_loot_info,
  msf_module_results, msf_running_stats, msf_session_list,
  msf_session_read;
* dangerous (disabled by default, enabled with
  ``--enable-dangerous-actions`` / ``MSF_MCP_DANGEROUS_ACTIONS=true``):
  msf_module_execute, msf_module_check, msf_session_stop,
  msf_session_write.

This module is the single definition of what the panel may ask
``msfmcpd`` to do, and of the guardrails around it:

* target allowlist, checked by syntax only: exactly ``contaia.site``
  and ``127.0.0.1`` — no DNS resolution, no private networks, no
  CIDR, no other loopback, no ``file:`` RHOSTS;
* ``LHOST`` is always ``127.0.0.1``: the handler listens on
  loopback only, never on ``0.0.0.0`` or a public address;
* reverse payloads (``PAYLOAD`` containing "reverse") are never left
  without a handler: before the exploit runs, the backend starts
  ``exploit/multi/handler`` as a background job through the SAME
  MCP connection (``msf_module_execute``), with the same payload,
  ``LHOST`` 127.0.0.1, ``LPORT`` and ``ExitOnSession`` false. The
  handler job lives in the Metasploit framework (msfrpcd), not in
  the MCP connection: MCP calls are stateless JSON-RPC, so the
  listener survives the HTTP request that started it and no second
  connection is needed. Incoming sessions are linked to the run by
  polling ``msf_session_list`` and matching target host / module /
  payload / local tunnel port. See ``web-ui/msf/README.md``;
* options are validated against the shapes in the official doc
  (option keys: identifier segments joined by ``::`` or ``-``,
  max 128 chars; max 100 keys; scalar values only; strings max
  8 KB; 64 KB aggregate);
* secrets (password-like option keys) are redacted before anything
  is written to disk or returned in a manifest; the MCP Bearer
  token never goes into a manifest, a log or the repository — it
  comes from the ``MSF_MCP_AUTH_TOKEN`` environment variable or
  from the dialog's password field, and lives only in memory.

This file never runs Metasploit, msfrpcd or msfmcpd by itself and
never contacts a target: it only validates and speaks MCP to the
local ``msfmcpd`` at ``MSF_MCP_URL`` (default
http://127.0.0.1:3000/ — the default HTTP transport of msfmcpd).
"""

import ipaddress
import json
import os
import re
import urllib.error
import urllib.request

DEFAULT_MCP_URL = "http://127.0.0.1:3000/"
DEFAULT_TIMEOUT = 30
STATUS_TIMEOUT = 5

ALLOWED_TARGETS = ("contaia.site", "127.0.0.1")
ALLOWED_LOCAL_HOST = "127.0.0.1"
DEFAULT_LPORT = 4444

MODULE_TYPES = (
    "exploit", "auxiliary", "post", "payload",
    "encoder", "evasion", "nop",
)
# Module types msf_module_execute accepts (official doc).
EXECUTE_TYPES = ("exploit", "auxiliary", "post", "payload", "evasion")
# Module types msf_module_check accepts (official doc).
CHECK_TYPES = ("exploit", "auxiliary")
ACTIONS = ("check", "run")

# The four dangerous tools of the official MCP server.
DANGEROUS_TOOLS = (
    "msf_module_execute", "msf_module_check",
    "msf_session_stop", "msf_session_write",
)

HANDLER_TYPE = "exploit"
HANDLER_NAME = "multi/handler"

# Option keys that carry a target host.
TARGET_OPTION_KEYS = ("RHOST", "RHOSTS")
# Option keys that carry the callback address / port of a payload.
CALLBACK_HOST_KEYS = ("LHOST",)
CALLBACK_PORT_KEYS = ("LPORT", "SRVPORT")
PORT_KEYS = ("RPORT", "LPORT", "SRVPORT")

MAX_OPTION_KEYS = 100
MAX_OPTION_KEY_LEN = 128
MAX_STRING_VALUE = 8 * 1024
MAX_OPTIONS_BYTES = 64 * 1024

_OPTION_KEY = re.compile(r"^[A-Za-z0-9]+((::|-)[A-Za-z0-9]+)*$")
_MODULE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_/.\-]*$")
_SECRET_KEY = re.compile(
    r"password|passwd|pass|token|secret|api[-_]?key|cookie|bearer",
    re.IGNORECASE)


class ValidationError(ValueError):
    """A request failed a panel-side guardrail check."""


class MsfError(Exception):
    """The MCP server could not be reached or answered with an error."""


class MsfToolError(MsfError):
    """msfmcpd answered a tools/call with isError: true."""

    def __init__(self, message, tool=None):
        super().__init__(message)
        self.tool = tool


class MsfNotConnected(MsfError):
    """No MCP server answered at MSF_MCP_URL."""


# -- validation -------------------------------------------------------

def validate_target_host(value):
    """Return the canonical target host, or raise ValidationError.

    Syntax only: no DNS resolution and no network contact. Only the
    exact allowlist ``contaia.site`` / ``127.0.0.1`` passes. Used
    for RHOST / RHOSTS values (bare hosts, no scheme, no CIDR).
    """
    if not isinstance(value, str):
        raise ValidationError("target debe ser texto")
    host = value.strip()
    if not host or len(host) > 253:
        raise ValidationError("target no válido")
    if any(c.isspace() for c in host) or "/" in host or ":" in host:
        raise ValidationError("target no válido: solo host simple")
    if host.startswith("-") or ".." in host:
        raise ValidationError("target no válido")
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", host):
        raise ValidationError("target no válido: caracteres no permitidos")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if str(ip) != "127.0.0.1":
            raise ValidationError("target fuera del alcance permitido")
    elif host not in ALLOWED_TARGETS:
        raise ValidationError(
            "target fuera del alcance permitido: solo contaia.site "
            "y 127.0.0.1")
    return host


def validate_module_type(value, allowed=MODULE_TYPES):
    if not isinstance(value, str) or value not in allowed:
        raise ValidationError(
            "tipo de módulo no permitido: %s (permitidos: %s)"
            % (value, ", ".join(allowed)))
    return value


def validate_module_name(name):
    if not isinstance(name, str) or not name or len(name) > 128:
        raise ValidationError("nombre de módulo no válido")
    if ".." in name or name.startswith("/") or " " in name:
        raise ValidationError("nombre de módulo no válido")
    if not _MODULE_NAME.fullmatch(name):
        raise ValidationError("nombre de módulo no válido")
    return name


def validate_option_key(key):
    if (not isinstance(key, str) or not key
            or len(key) > MAX_OPTION_KEY_LEN
            or not _OPTION_KEY.fullmatch(key)):
        raise ValidationError("nombre de opción no válido: %r" % (key,))
    return key


def validate_options(options):
    """Validate a module datastore options dict; return a clean copy.

    Mirrors the official doc's input validation: scalar values only,
    max 100 keys, strings max 8 KB, 64 KB aggregate. Target options
    (RHOST/RHOSTS) must pass the allowlist; LHOST must be exactly
    127.0.0.1; ports must be 1-65535.
    """
    if options is None:
        return {}
    if not isinstance(options, dict):
        raise ValidationError("options debe ser un objeto JSON")
    if len(options) > MAX_OPTION_KEYS:
        raise ValidationError(
            "demasiadas opciones (máximo %d)" % MAX_OPTION_KEYS)
    clean = {}
    total = 0
    for key, value in options.items():
        validate_option_key(key)
        if value is None or isinstance(value, (str, int, float, bool)):
            pass
        else:
            raise ValidationError(
                "la opción %s debe ser un valor simple (texto, número "
                "o booleano)" % key)
        if isinstance(value, str):
            if len(value.encode("utf-8")) > MAX_STRING_VALUE:
                raise ValidationError(
                    "la opción %s supera los 8 KB" % key)
            total += len(value.encode("utf-8"))
        if isinstance(value, bool):
            pass
        elif isinstance(value, (int, float)) and isinstance(value, float) \
                and (value != value or value in (float("inf"), float("-inf"))):
            raise ValidationError("la opción %s no es un número válido" % key)
        clean[key] = value
    if total > MAX_OPTIONS_BYTES:
        raise ValidationError("las opciones superan los 64 KB en total")
    for key in TARGET_OPTION_KEYS:
        if key in clean:
            raw = clean[key]
            if not isinstance(raw, str) or not raw.strip():
                raise ValidationError("la opción %s debe ser texto" % key)
            hosts = [h for h in (part.strip() for part in raw.split(","))
                     if h]
            if not hosts:
                raise ValidationError("la opción %s está vacía" % key)
            for host in hosts:
                validate_target_host(host)
    for key in CALLBACK_HOST_KEYS:
        if key in clean:
            # El handler escucha en local y nada más: LHOST solo
            # 127.0.0.1, nunca 0.0.0.0 ni una IP pública.
            if clean[key] != ALLOWED_LOCAL_HOST:
                raise ValidationError(
                    "LHOST solo puede ser 127.0.0.1 (el handler "
                    "escucha en local; no se expone a 0.0.0.0)")
    for key in PORT_KEYS:
        if key in clean:
            port = clean[key]
            if isinstance(port, str):
                if not port.isdigit():
                    raise ValidationError(
                        "la opción %s debe ser un puerto" % key)
                port = int(port)
            if not isinstance(port, int) or isinstance(port, bool) \
                    or not 1 <= port <= 65535:
                raise ValidationError(
                    "la opción %s debe ser un puerto 1-65535" % key)
            clean[key] = port
    return clean


def is_reverse_payload(options):
    """True when the PAYLOAD option names a reverse payload."""
    payload = (options or {}).get("PAYLOAD")
    return isinstance(payload, str) and "reverse" in payload.lower()


def apply_reverse_defaults(options):
    """Fill the callback defaults of a reverse payload, explicitly.

    A reverse payload without LHOST/LPORT gets LHOST 127.0.0.1 and
    LPORT 4444 (the Metasploit defaults for reverse_tcp). Returns
    (options, notes): notes name every default applied, so the plan
    the user confirms shows them instead of hiding them.
    """
    options = dict(options or {})
    notes = []
    if not is_reverse_payload(options):
        return options, notes
    if "LHOST" not in options:
        options["LHOST"] = ALLOWED_LOCAL_HOST
        notes.append("LHOST por defecto: 127.0.0.1 (handler local)")
    if "LPORT" not in options:
        options["LPORT"] = DEFAULT_LPORT
        notes.append("LPORT por defecto: 4444")
    return options, notes


def handler_spec(options):
    """The multi/handler job a reverse payload needs, or None.

    The handler runs the SAME payload against the same callback, so
    the session the exploit opens has a listener waiting for it.
    ``ExitOnSession`` false: the handler stays up for the session
    and for later ones instead of dying on the first connection.
    """
    if not is_reverse_payload(options):
        return None
    payload = options.get("PAYLOAD")
    return {
        "type": HANDLER_TYPE,
        "name": HANDLER_NAME,
        "options": {
            "PAYLOAD": payload,
            "LHOST": options.get("LHOST", ALLOWED_LOCAL_HOST),
            "LPORT": options.get("LPORT", DEFAULT_LPORT),
            "ExitOnSession": False,
        },
    }


def redact_options(options):
    """Copy of options with secret-looking values replaced by ***."""
    clean = {}
    for key, value in (options or {}).items():
        if _SECRET_KEY.search(key):
            clean[key] = "***"
        else:
            clean[key] = value
    return clean


def validate_session_id(value):
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValidationError("session_id no válido")
    return value


def validate_msf_plan(payload):
    """Validate a /api/msf/plan payload; returns the clean plan.

    The plan is only a description of what would run: module, type,
    action (check|run), validated options, whether it is a reverse
    payload (and then the handler job it needs, with its defaults
    made explicit). Nothing is executed here.
    """
    if not isinstance(payload, dict):
        raise ValidationError("el cuerpo debe ser un objeto JSON")
    module_type = validate_module_type(payload.get("type"))
    name = validate_module_name(payload.get("name"))
    action = payload.get("action")
    if action not in ACTIONS:
        raise ValidationError("action debe ser check o run")
    if action == "check" and module_type not in CHECK_TYPES:
        raise ValidationError(
            "check solo admite módulos exploit o auxiliary")
    if action == "run" and module_type not in EXECUTE_TYPES:
        raise ValidationError(
            "run no admite módulos de tipo %s" % module_type)
    options = validate_options(payload.get("options"))
    options, notes = apply_reverse_defaults(options)
    reverse = is_reverse_payload(options)
    return {
        "type": module_type,
        "name": name,
        "action": action,
        "options": options,
        "options_redacted": redact_options(options),
        "reverse": reverse,
        "handler": handler_spec(options),
        "notes": notes,
    }


def plan_summary(plan):
    """One-line-per-field summary of a plan, for the console."""
    lines = [
        "módulo: %s/%s" % (plan["type"], plan["name"]),
        "acción: %s" % plan["action"],
    ]
    for key in sorted(plan["options_redacted"]):
        lines.append("  %s = %s" % (key, plan["options_redacted"][key]))
    if plan["reverse"]:
        handler = plan["handler"]
        lines.append("payload reverse: sí — handler exploit/multi/handler "
                     "antes del exploit")
        lines.append("  handler: PAYLOAD=%s LHOST=%s LPORT=%s "
                     "ExitOnSession=false" % (
                         handler["options"]["PAYLOAD"],
                         handler["options"]["LHOST"],
                         handler["options"]["LPORT"]))
    for note in plan["notes"]:
        lines.append("nota: " + note)
    return "\n".join(lines)


# -- MCP client ---------------------------------------------------------

def mcp_url_from_env():
    return os.environ.get("MSF_MCP_URL") or DEFAULT_MCP_URL


def mcp_token_from_env():
    return os.environ.get("MSF_MCP_AUTH_TOKEN") or None


class MsfMcpClient:
    """Minimal MCP JSON-RPC 2.0 client over HTTP (stdlib only).

    One client per request: ``initialize`` + ``tools/list`` /
    ``tools/call`` against the msfmcpd HTTP transport. The server
    answers either a JSON object (Streamable HTTP) or an SSE stream
    (``data: {...}`` lines); both are parsed. The ``Mcp-Session-Id``
    header, when the server sends one, is reused on later calls.
    """

    def __init__(self, url=None, token=None, timeout=DEFAULT_TIMEOUT):
        self.url = url or mcp_url_from_env()
        if not isinstance(self.url, str) or not self.url.startswith(
                ("http://127.0.0.1", "http://localhost")):
            raise ValidationError(
                "MSF_MCP_URL solo puede apuntar a 127.0.0.1/localhost")
        self.token = token if token is not None else mcp_token_from_env()
        self.timeout = timeout
        self.session_id = None
        self._next_id = 1
        self._tools = None
        self._initialized = False

    def _headers(self):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def _parse_response_body(self, body):
        text = body.decode("utf-8", errors="replace").strip()
        if not text:
            raise MsfError("respuesta vacía de msfmcpd")
        if text.startswith("{"):
            return json.loads(text)
        # SSE stream: take the last data: line that parses as JSON.
        data = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                candidate = line[5:].strip()
                if candidate and candidate != "[DONE]":
                    try:
                        data = json.loads(candidate)
                    except ValueError:
                        continue
        if data is None:
            raise MsfError("respuesta no JSON de msfmcpd")
        return data

    def _request(self, method, params=None):
        # El protocolo MCP exige initialize antes que cualquier otra
        # petición: se hace perezosamente en la primera llamada.
        if method != "initialize" and not self._initialized:
            self.initialize()
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
        }
        self._next_id += 1
        if params is not None:
            payload["params"] = params
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                session_id = resp.headers.get("Mcp-Session-Id")
                if session_id:
                    self.session_id = session_id
                body = resp.read()
        except urllib.error.HTTPError as exc:
            raise MsfError(
                "msfmcpd respondió HTTP %d" % exc.code)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise MsfNotConnected(
                "no se pudo conectar con msfmcpd en %s (%s)"
                % (self.url, exc))
        try:
            response = self._parse_response_body(body)
        except ValueError as exc:
            raise MsfError("respuesta no válida de msfmcpd: %s" % exc)
        if not isinstance(response, dict) or "result" not in response:
            error = (response or {}).get("error") or {}
            raise MsfError("error MCP: %s" % (
                error.get("message") or "respuesta sin result"))
        return response["result"]

    def _notify(self, method):
        payload = {"jsonrpc": "2.0", "method": method}
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout):
                pass
        except Exception:
            # Notifications are best-effort; a failure here does not
            # mean the session is unusable.
            pass

    def initialize(self):
        self._initialized = True
        try:
            result = self._request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pentestx-web-ui", "version": "1.0"},
            })
        except Exception:
            self._initialized = False
            raise
        self._notify("notifications/initialized")
        return result

    def tools_list(self):
        if self._tools is not None:
            return self._tools
        result = self._request("tools/list")
        tools = result.get("tools") or []
        self._tools = [t.get("name") for t in tools
                       if isinstance(t, dict) and t.get("name")]
        return self._tools

    def dangerous_actions_enabled(self):
        """True/False from tools/list, None when it cannot be told.

        Disabled dangerous tools are absent from the tool list the
        server advertises; when the list cannot be read at all, the
        caller must try the call and map its tool error instead.
        """
        try:
            tools = self.tools_list()
        except MsfError:
            return None
        return "msf_module_execute" in tools

    def call_tool(self, name, arguments=None):
        """Call one msfmcpd tool; returns the parsed data envelope.

        The official doc wraps every successful tool response in
        ``{"metadata": {...}, "data": ...}`` as JSON text content.
        A tool error (``isError: true``) raises MsfToolError with
        the server's message.
        """
        result = self._request("tools/call", {
            "name": name,
            "arguments": arguments or {},
        })
        if result.get("isError"):
            texts = []
            for item in result.get("content") or []:
                if isinstance(item, dict) and item.get("text"):
                    texts.append(str(item["text"]))
            raise MsfToolError(
                " ".join(texts) or "error de la herramienta %s" % name,
                tool=name)
        texts = []
        for item in result.get("content") or []:
            if isinstance(item, dict) and item.get("text"):
                texts.append(str(item["text"]))
        text = "\n".join(texts)
        if not text:
            return None
        try:
            envelope = json.loads(text)
        except ValueError:
            return {"text": text}
        if isinstance(envelope, dict) and "data" in envelope:
            return envelope["data"]
        return envelope

    # -- read-only tools (official doc) --------------------------------
    def search_modules(self, query, limit=100):
        if not isinstance(query, str) or not query.strip():
            raise ValidationError("query de búsqueda obligatoria")
        if len(query) > 500:
            raise ValidationError("query demasiado larga (máximo 500)")
        limit = int(limit) if str(limit).isdigit() else 100
        limit = max(1, min(1000, limit))
        return self.call_tool("msf_search_modules",
                              {"query": query, "limit": limit})

    def module_info(self, module_type, name):
        return self.call_tool("msf_module_info", {
            "type": validate_module_type(module_type),
            "name": validate_module_name(name),
        })

    def host_info(self, workspace="default", limit=100):
        return self.call_tool("msf_host_info",
                              {"workspace": workspace, "limit": limit})

    def service_info(self, workspace="default", limit=100):
        return self.call_tool("msf_service_info",
                              {"workspace": workspace, "limit": limit})

    def vulnerability_info(self, workspace="default", limit=100):
        return self.call_tool("msf_vulnerability_info",
                              {"workspace": workspace, "limit": limit})

    def session_list(self):
        return self.call_tool("msf_session_list")

    def module_results(self, uuid):
        if not isinstance(uuid, str) or not uuid:
            raise ValidationError("uuid obligatorio")
        return self.call_tool("msf_module_results", {"uuid": uuid})

    def running_stats(self):
        return self.call_tool("msf_running_stats")

    # -- dangerous tools (official doc, gated by the server) -----------
    def module_execute(self, module_type, name, options):
        return self.call_tool("msf_module_execute", {
            "type": validate_module_type(module_type, EXECUTE_TYPES),
            "name": validate_module_name(name),
            "options": validate_options(options),
        })

    def module_check(self, module_type, name, options):
        return self.call_tool("msf_module_check", {
            "type": validate_module_type(module_type, CHECK_TYPES),
            "name": validate_module_name(name),
            "options": validate_options(options),
        })

    def session_stop(self, session_id):
        return self.call_tool("msf_session_stop", {
            "session_id": validate_session_id(session_id),
        })
