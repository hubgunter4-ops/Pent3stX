"""Pent3stX — motor de planificación por reglas (v1).

Determinista y auditable: a partir de un goal, un target, el scope,
la referencia de autorización y el estado del mapeo (herramientas
instaladas, sesiones existentes), genera un plan de pasos ordenados
sin ejecutar nada. Cada regla está escrita aquí y documentada en
``web-ui/engine/DESIGN.md``. No hay LLM ni caja negra.

El plan se ejecuta en ``web-ui/server.py`` paso a paso: cada paso
hace su propio dry-run del comando exacto y verifica sus
precondiciones antes de ejecutarse. La re-planificación
(``replan``) es una función pura: ajusta un plan ante fallos sin
re-ejecutar lo ya hecho.

Guardrails (ver DESIGN.md §7):

* targets solo de la allowlist: ``contaia.site`` y ``127.0.0.1``
  (y ``http://127.0.0.1:8080/moodle`` solo para los pasos Moodle);
* acciones y pipelines solo de las allowlists existentes;
* sin RCE, sin escalada, sin escritura en la BD, sin herramientas
  fuera de la allowlist;
* la autorización es una casilla por ejecución
  (``confirm_written_authorization``): no hay ningún campo de texto
  para escribir una referencia en la interfaz, y el motor nunca
  inventa una. La referencia que exige la CLI vive en ``scope.yaml``
  (la CLI la toma de ahí); un plan sin casilla marcada dice
  explícitamente "sin autorización confirmada" y solo sirve como
  medición del scope;
* los pasos Moodle nunca extraen ``password``;
* la sesskey y la cookie nunca aparecen en claro en un plan
  generado: el comando de muestra las redacta.

Solo librería estándar. No toca red ni disco: el llamador (el
servidor) aporta el mapeo y guarda la evidencia.
"""

import copy
import hashlib
import json
import os
import sys
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
WEB_UI_DIR = ENGINE_DIR.parent
# Misma regla que web-ui/server.py: PENTESTX_ROOT permite probar el
# motor contra un repo simulado; por defecto, la raíz del repo es el
# padre de web-ui/.
REPO_ROOT = Path(os.environ.get("PENTESTX_ROOT", WEB_UI_DIR.parent))
PENTESTX = REPO_ROOT / "pentestx.py"
MOODLE_SQLI = WEB_UI_DIR / "tools" / "moodle_sqli.py"
MOODLE_BASE_URL = "http://127.0.0.1:8080/moodle"

MAX_STEPS = 12

ALLOWED_TARGETS = ("contaia.site", "127.0.0.1")
ALLOWED_SCOPES = ("passive", "active")
ALLOWED_ACTIONS = (
    "passive", "active", "web", "ports", "vuln", "owasp_web",
    "vulnerability", "correlate", "report", "correlated",
    # "intrusive" es una acción válida de la CLI (ACTIVE_ACTIONS en
    # pentestx.py) y la usa el goal full_assessment; el servidor
    # también la permite (ver server.py) y exige scope active.
    "intrusive",
)
ALLOWED_PIPELINES = ("standard", "with_intrusive", "with_owasp", "full_web")
# Pipelines cuyos pasos incluyen trabajo intrusivo/activo.
PIPELINES_NEEDING_ACTIVE_SCOPE = ("with_intrusive", "full_web")

class ValidationError(ValueError):
    """Una entrada del plan no pasó un guardrail."""


# -- goals ------------------------------------------------------------
# Cada goal fija su pipeline y sus pasos. Un paso es un dict con:
#   id, action, tool ("pentestx" | "moodle_sqli"), preconditions
#   (lista de dicts, ver check_preconditions), expected_evidence,
#   on_fail ("stop" | "skip") y note. El estado ("pending",
#   "blocked", "skipped_missing_dependency"...) se calcula al
#   generar el plan, según el mapeo.

GOALS = {
    "owasp_report": {
        "description": (
            "Informe OWASP: clasificación pasiva, escaneo OWASP web "
            "(comprobador propio con urllib), candidatos de "
            "vulnerabilidad, correlación y reporte. No necesita "
            "ninguna herramienta externa."),
        "pipeline_profile": "with_owasp",
        "scope": "passive",
        "requires": ["pentestx.py"],
        "steps": [
            {
                "id": "passive", "action": "passive", "tool": "pentestx",
                "preconditions": [],
                "expected_evidence": (
                    "execution_manifest.json de la sesión"),
                "on_fail": "stop",
                "note": "Clasifica el target sin resolverlo ni contactarlo.",
            },
            {
                "id": "owasp_web", "action": "owasp_web", "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok", "step": "passive"}],
                "expected_evidence": (
                    "OWASP_WEB_REPORT.md + owasp_findings.json de la sesión"),
                "on_fail": "stop",
                "note": "Escaneo OWASP web con urllib (sin ZAP).",
            },
            {
                "id": "vulnerability", "action": "vulnerability",
                "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok", "step": "owasp_web"}],
                "expected_evidence": (
                    "vulnerability_review.json de la sesión"),
                "on_fail": "skip",
                "note": "Candidatos de vulnerabilidad a partir de los findings.",
            },
            {
                "id": "correlate", "action": "correlate", "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok_or_skipped",
                     "step": "vulnerability"}],
                "expected_evidence": "attack_chains.json de la sesión",
                "on_fail": "skip",
                "note": "Correlación local de findings.",
            },
            {
                "id": "report", "action": "report", "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok_or_skipped",
                     "step": "correlate"}],
                "expected_evidence": "reporte de la sesión",
                "on_fail": "stop",
                "note": "Genera el reporte de la sesión.",
            },
        ],
    },
    "full_assessment": {
        "description": (
            "Evaluación completa: pasiva, activa e intrusiva con nmap, "
            "OWASP web, vulnerabilidad, correlación y reporte. Exige "
            "scope active y nmap instalado; sin nmap, los pasos activos "
            "se saltan con aviso y el resto continúa."),
        "pipeline_profile": "full_web",
        "scope": "active",
        "requires": ["pentestx.py", "nmap"],
        "steps": [
            {
                "id": "passive", "action": "passive", "tool": "pentestx",
                "preconditions": [],
                "expected_evidence": (
                    "execution_manifest.json de la sesión"),
                "on_fail": "stop",
                "note": "Clasifica el target sin resolverlo ni contactarlo.",
            },
            {
                "id": "active", "action": "active", "tool": "pentestx",
                "preconditions": [
                    {"type": "tool_present", "tool": "nmap"},
                    {"type": "scope", "scope": "active"},
                ],
                "expected_evidence": (
                    "resultado de nmap -sn en la sesión"),
                "on_fail": "skip",
                "note": "Detección de hosts con nmap -sn (sin puertos).",
            },
            {
                "id": "intrusive", "action": "intrusive", "tool": "pentestx",
                "preconditions": [
                    {"type": "tool_present", "tool": "nmap"},
                    {"type": "scope", "scope": "active"},
                ],
                "expected_evidence": (
                    "nmap_*.stdout de la sesión (puertos acotados)"),
                "on_fail": "skip",
                "note": "Escaneo intrusivo acotado con nmap -sT -sV.",
            },
            {
                "id": "owasp_web", "action": "owasp_web", "tool": "pentestx",
                "preconditions": [],
                "expected_evidence": (
                    "OWASP_WEB_REPORT.md + owasp_findings.json de la sesión"),
                "on_fail": "stop",
                "note": "Escaneo OWASP web con urllib (sin ZAP).",
            },
            {
                "id": "vulnerability", "action": "vulnerability",
                "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok", "step": "owasp_web"}],
                "expected_evidence": (
                    "vulnerability_review.json de la sesión"),
                "on_fail": "skip",
                "note": "Candidatos de vulnerabilidad a partir de los findings.",
            },
            {
                "id": "correlate", "action": "correlate", "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok_or_skipped",
                     "step": "vulnerability"}],
                "expected_evidence": "attack_chains.json de la sesión",
                "on_fail": "skip",
                "note": "Correlación local de findings.",
            },
            {
                "id": "report", "action": "report", "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok_or_skipped",
                     "step": "correlate"}],
                "expected_evidence": "reporte de la sesión",
                "on_fail": "stop",
                "note": "Genera el reporte de la sesión.",
            },
        ],
    },
    "moodle_sqli_confirm": {
        "description": (
            "Confirmar SQLi en el Moodle local (CVE-2021-36393): "
            "clasificación pasiva, sonda de detección por tiempo y, "
            "si es vulnerable, extracción acotada de database() y "
            "username (nunca password), correlación y reporte. Exige "
            "sesskey y cookie MoodleSession vigentes."),
        "pipeline_profile": "with_owasp",
        "scope": "passive",
        "requires": ["pentestx.py", "moodle_sqli.py", "sesión Moodle vigente"],
        "steps": [
            {
                "id": "passive", "action": "passive", "tool": "pentestx",
                "preconditions": [],
                "expected_evidence": (
                    "execution_manifest.json de la sesión"),
                "on_fail": "stop",
                "note": "Clasifica el target sin resolverlo ni contactarlo.",
            },
            {
                "id": "moodle_detect", "action": "moodle_detect",
                "tool": "moodle_sqli",
                "preconditions": [{"type": "moodle_session"}],
                "expected_evidence": (
                    "resultado vulnerable true/false de la sonda"),
                "on_fail": "stop",
                "note": (
                    "Sonda de detección SLEEP + un solo carácter "
                    "(sin extracción completa)."),
            },
            {
                "id": "moodle_extract", "action": "moodle_extract",
                "tool": "moodle_sqli",
                "preconditions": [{"type": "moodle_vulnerable"}],
                "expected_evidence": (
                    "database() y username en el manifiesto de la sonda"),
                "on_fail": "stop",
                "note": (
                    "Extracción acotada: database y username, "
                    "nunca password."),
            },
            {
                "id": "correlate", "action": "correlate", "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok_or_skipped",
                     "step": "moodle_extract"}],
                "expected_evidence": "attack_chains.json de la sesión",
                "on_fail": "skip",
                "note": "Correlación local de findings.",
            },
            {
                "id": "report", "action": "report", "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok_or_skipped",
                     "step": "correlate"}],
                "expected_evidence": "reporte de la sesión",
                "on_fail": "stop",
                "note": "Genera el reporte de la sesión.",
            },
        ],
    },
    "msf_targeted": {
        "description": (
            "Objetivo fijado con Metasploit: mapeo de sesiones y "
            "findings existentes, candidatos de vulnerabilidad, "
            "correlación findings → módulos Metasploit (solo lectura "
            "del MCP), check del módulo correlacionado y ejecución "
            "solo con casilla, y reporte. Exige msfmcpd conectado y "
            "las acciones peligrosas activadas para ejecutar."),
        "pipeline_profile": "with_owasp",
        "scope": "active",
        "requires": ["pentestx.py", "msfmcpd"],
        "steps": [
            {
                "id": "mapping", "action": "mapping", "tool": "engine",
                "preconditions": [],
                "expected_evidence": (
                    "sesiones y findings del objetivo fijado en el "
                    "resultado del paso"),
                "on_fail": "stop",
                "note": (
                    "Mapeo: lee las sesiones y findings existentes "
                    "del objetivo fijado, sin escanear nada nuevo."),
            },
            {
                "id": "vulnerability", "action": "vulnerability",
                "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok", "step": "mapping"}],
                "expected_evidence": (
                    "vulnerability_review.json de la sesión"),
                "on_fail": "skip",
                "note": "Candidatos de vulnerabilidad a partir de los findings del mapeo.",
            },
            {
                "id": "correlate", "action": "correlate", "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok_or_skipped",
                     "step": "vulnerability"}],
                "expected_evidence": "attack_chains.json de la sesión",
                "on_fail": "skip",
                "note": "Correlación local de findings.",
            },
            {
                "id": "msf_correlate", "action": "msf_correlate",
                "tool": "msf",
                "preconditions": [
                    {"type": "previous_step_ok_or_skipped",
                     "step": "correlate"}],
                "expected_evidence": (
                    "tabla finding → módulos candidatos en el "
                    "resultado del paso"),
                "on_fail": "skip",
                "note": (
                    "Correlación findings → módulos Metasploit "
                    "(solo lectura del MCP, sin casilla). Sin "
                    "candidatos queda skipped y el plan sigue."),
            },
            {
                "id": "msf_check", "action": "msf_check", "tool": "msf",
                "preconditions": [{"type": "msf_candidates"}],
                "expected_evidence": (
                    "resultado del check del módulo correlacionado"),
                "on_fail": "skip",
                "note": (
                    "Check del módulo correlacionado de mayor "
                    "rango. Sin casilla queda blocked."),
            },
            {
                "id": "msf_run", "action": "msf_run", "tool": "msf",
                "preconditions": [{"type": "msf_checked"}],
                "expected_evidence": (
                    "manifiesto en workspace/msf_runs/ + sesiones "
                    "vinculadas"),
                "on_fail": "stop",
                "note": (
                    "Ejecuta el módulo correlacionado. Solo con "
                    "casilla y acciones peligrosas activadas; un "
                    "payload reverse arranca antes su handler por "
                    "la misma conexión MCP."),
            },
            {
                "id": "report", "action": "report", "tool": "pentestx",
                "preconditions": [
                    {"type": "previous_step_ok_or_skipped",
                     "step": "msf_run"}],
                "expected_evidence": "reporte de la sesión",
                "on_fail": "stop",
                "note": "Genera el reporte de la sesión.",
            },
        ],
    },
}


def list_goals():
    """Los goals disponibles, con descripción y requisitos."""
    return [
        {
            "goal": name,
            "description": spec["description"],
            "pipeline_profile": spec["pipeline_profile"],
            "scope": spec["scope"],
            "requires": list(spec["requires"]),
            "steps": [s["id"] for s in spec["steps"]],
        }
        for name, spec in GOALS.items()
    ]


# -- validación -------------------------------------------------------


def validate_target(target):
    """Solo la allowlist, por sintaxis (sin resolver ni contactar)."""
    if not isinstance(target, str) or not target.strip():
        raise ValidationError("target es obligatorio")
    value = target.strip()
    if value not in ALLOWED_TARGETS:
        raise ValidationError(
            "target fuera del alcance permitido: solo %s"
            % " y ".join(ALLOWED_TARGETS))
    return value


def validate_confirmation(value):
    """La casilla de autorización: debe ser un booleano.

    ``True`` significa "Confirmo que tengo autorización escrita
    para este alcance". Ausente equivale a ``False`` (sin
    autorización confirmada). Cualquier otro tipo se rechaza:
    la confirmación no es texto.
    """
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValidationError(
            "confirm_written_authorization debe ser true o false")
    return value


def validate_plan_structure(plan):
    """Un plan generado debe cumplir los límites estructurales."""
    if not isinstance(plan, dict):
        raise ValidationError("el plan debe ser un objeto")
    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValidationError("el plan debe tener al menos un paso")
    if len(steps) > MAX_STEPS:
        raise ValidationError(
            "el plan tiene %d pasos, más del máximo %d"
            % (len(steps), MAX_STEPS))
    ids = [s.get("id") for s in steps]
    if len(set(ids)) != len(ids):
        raise ValidationError("pasos duplicados en el plan")
    for step in steps:
        if step.get("tool") == "pentestx" and step.get("action") not in ALLOWED_ACTIONS:
            raise ValidationError(
                "acción no permitida en el paso %s: %s"
                % (step.get("id"), step.get("action")))
        if step.get("on_fail") not in ("stop", "skip"):
            raise ValidationError(
                "on_fail no válido en el paso %s" % step.get("id"))
    return plan


def plan_hash(plan):
    """Hash del plan aprobado (sin secretos: el plan no los contiene)."""
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


# -- comandos de dry-run ----------------------------------------------


def build_pentestx_command(plan, step, dry_run=True):
    """Comando exacto de la CLI para un paso pentestx."""
    command = [
        sys.executable,
        str(PENTESTX),
        "--target", plan["target"],
        "--scope", plan["scope"],
        "--action", step["action"],
        "--pipeline-profile", plan["pipeline_profile"],
        "--confirm-written-authorization",
    ]
    # La referencia que exige la CLI vive en scope.yaml: la CLI la
    # toma de ahí (--scope-file si existe). Este comando nunca lleva
    # --authorization-reference: en la interfaz no hay ningún campo
    # de texto para escribir una.
    if (REPO_ROOT / "scope.yaml").exists():
        command += ["--scope-file", "scope.yaml"]
    if dry_run:
        command.append("--dry-run")
    return command


def build_moodle_command(plan, step, dry_run=True):
    """Comando de muestra de un paso Moodle, con secretos redactados.

    El comando real (con sesskey y cookie) solo lo construye el
    servidor a partir de la petición aprobada en memoria.
    """
    if step["id"] == "moodle_detect":
        extract = ["database"]
        max_chars = "1"
    else:
        extract = ["database", "username"]
        max_chars = "50"
    command = [
        sys.executable,
        str(MOODLE_SQLI),
        "--base-url", MOODLE_BASE_URL,
        "--sesskey", "<sesskey-redacted>",
        "--session-cookie", "<session-cookie-redacted>",
        "--extract", *extract,
        "--sleep", "3",
        "--timeout", "15",
        "--max-chars", max_chars,
        "--confirm-written-authorization",
    ]
    if dry_run:
        command.append("--dry-run")
    return command


def build_msf_command(plan, step):
    """Comando de muestra de un paso MSF (descripción, no se ejecuta).

    El módulo concreto se elige en tiempo de ejecución (el primer
    candidato de msf_correlate); el comando de muestra lo dice así
    en vez de inventar un módulo.
    """
    if step["id"] == "msf_correlate":
        return ["msfmcpd", "msf_search_modules", "--target", plan["target"],
                "(correlación findings → módulos, solo lectura)"]
    action = ("msf_module_check" if step["id"] == "msf_check"
              else "msf_module_execute")
    return ["msfmcpd", action, "--target", plan["target"],
            "--module", "<candidato de msf_correlate>"]


def build_engine_command(plan, step):
    """Comando de muestra del paso de mapeo (lectura local)."""
    return ["engine", "mapping", "--target", plan["target"]]


def build_dry_run_command(plan, step):
    if step["tool"] == "moodle_sqli":
        return build_moodle_command(plan, step, dry_run=True)
    if step["tool"] == "msf":
        return build_msf_command(plan, step)
    if step["tool"] == "engine":
        return build_engine_command(plan, step)
    return build_pentestx_command(plan, step, dry_run=True)


# -- precondiciones ----------------------------------------------------


def check_preconditions(step, context):
    """Devuelve (cumplida, motivo). ``context`` es el estado conocido:

    {
      "tools_available": {"nmap": bool, ...},
      "scope": "passive" | "active",
      "moodle_session": bool,
      "results": {step_id: {"status": "completed"|"failed"|..., ...}},
    }
    """
    results = context.get("results") or {}
    tools = context.get("tools_available") or {}
    for pre in step.get("preconditions") or []:
        kind = pre.get("type")
        if kind == "tool_present":
            if not tools.get(pre.get("tool")):
                return False, "%s no está instalado" % pre.get("tool")
        elif kind == "scope":
            if context.get("scope") != pre.get("scope"):
                return False, "scope debe ser %s" % pre.get("scope")
        elif kind == "previous_step_ok":
            # Sin resultado todavía, la precondición aún no es
            # decidible: se da por cumplida al planificar; el runner
            # la vuelve a comprobar justo antes de ejecutar el paso,
            # cuando el resultado ya existe.
            if pre.get("step") not in results:
                continue
            prev = results.get(pre.get("step")) or {}
            if prev.get("status") != "completed":
                return False, "el paso %s no terminó OK" % pre.get("step")
        elif kind == "previous_step_ok_or_skipped":
            if pre.get("step") not in results:
                continue
            prev = results.get(pre.get("step")) or {}
            if prev.get("status") not in (
                    "completed", "skipped", "skipped_missing_dependency"):
                return False, (
                    "el paso %s no terminó OK ni saltado" % pre.get("step"))
        elif kind == "moodle_session":
            if not context.get("moodle_session"):
                return False, (
                    "falta la sesión de Moodle (sesskey y cookie vigentes)")
        elif kind == "msf_candidates":
            # Sin resultado de msf_correlate todavía, aún no es
            # decidible (ver previous_step_ok): se da por cumplida
            # al planificar; el runner la vuelve a comprobar antes
            # de ejecutar el check, cuando el resultado ya existe.
            if "msf_correlate" not in results:
                continue
            corr = results.get("msf_correlate") or {}
            correlations = (corr.get("result") or {}).get("correlations")
            if correlations is None:
                correlations = corr.get("correlations") or []
            total = sum(len(c.get("modules") or [])
                        for c in correlations if isinstance(c, dict))
            if total == 0:
                return False, (
                    "msf_correlate no devolvió módulos candidatos")
        elif kind == "msf_checked":
            # Sin resultado de check todavía, aún no es decidible
            # (ver previous_step_ok): se da por cumplida al
            # planificar; el runner la vuelve a comprobar antes
            # de ejecutar el run.
            if "msf_check" not in results:
                continue
            prev = results.get("msf_check") or {}
            if prev.get("status") != "completed":
                return False, "el paso msf_check no terminó OK"
        elif kind == "moodle_vulnerable":
            # Sin resultado de detección todavía, aún no es decidible
            # (ver previous_step_ok): se da por cumplida al
            # planificar; el runner la vuelve a comprobar antes de
            # ejecutar la extracción.
            if "moodle_detect" not in results:
                continue
            det = results.get("moodle_detect") or {}
            result = det.get("result") or {}
            if result.get("vulnerable") is not True:
                return False, "la detección no confirmó la vulnerabilidad"
        else:
            return False, "precondición desconocida: %s" % kind
    return True, ""


# -- generación del plan -----------------------------------------------


def generate_plan(goal, target, scope, confirm_written_authorization=False,
                  mapping=None, moodle=None):
    """Genera el plan de un goal sin ejecutar nada.

    ``confirm_written_authorization`` es la casilla de la interfaz:
    True significa "Confirmo que tengo autorización escrita para
    este alcance". Si no se marca, el plan lleva
    ``confirm_written_authorization: False`` y la nota "sin
    autorización confirmada" (nunca se inventa una referencia).
    La referencia que exige la CLI vive en ``scope.yaml``: la CLI
    la toma de ahí al ejecutar; sin ella, la ejecución real se
    rechaza (ver ``web-ui/server.py``).

    ``mapping``: {"tools_available": {"nmap": bool, ...},
    "sessions": [...], "findings": int} (todo opcional).
    ``moodle``: {"base_url": ..., "sesskey_present": bool,
    "cookie_present": bool} o None.
    """
    if goal not in GOALS:
        raise ValidationError(
            "goal no permitido: %s (goals: %s)"
            % (goal, ", ".join(sorted(GOALS))))
    spec = GOALS[goal]
    target = validate_target(target)
    confirmed = validate_confirmation(confirm_written_authorization)
    if scope not in ALLOWED_SCOPES:
        raise ValidationError("scope debe ser passive o active")
    if scope != spec["scope"]:
        raise ValidationError(
            "el goal %s exige scope %s, no %s"
            % (goal, spec["scope"], scope))
    pipeline = spec["pipeline_profile"]
    if pipeline in PIPELINES_NEEDING_ACTIVE_SCOPE and scope != "active":
        raise ValidationError(
            "el pipeline %s exige scope active" % pipeline)

    mapping = mapping or {}
    tools_available = mapping.get("tools_available") or {}
    moodle_session = bool(
        moodle
        and moodle.get("sesskey_present")
        and moodle.get("cookie_present")
        and moodle.get("base_url", MOODLE_BASE_URL) == MOODLE_BASE_URL)

    plan = {
        "goal": goal,
        "target": target,
        "scope": scope,
        "pipeline_profile": pipeline,
        "confirm_written_authorization": confirmed,
        "authorization_note": (
            "autorización confirmada por casilla, sin referencia "
            "en la interfaz"
            if confirmed else
            "sin autorización confirmada"),
        "warnings": [],
        "steps": [],
    }
    if goal == "msf_targeted":
        # Los findings del mapeo viajan con el plan: el paso
        # msf_correlate los usa (y el paso mapping los vuelve a
        # leer en ejecución). No son secretos: son findings de
        # sesiones propias ya guardadas en disco.
        plan["msf_findings"] = list((mapping.get("findings") or [])[:50])
    # Contexto para evaluar el gating al generar el plan (sin
    # resultados todavía: previous_step_ok se evalúa en ejecución).
    context = {
        "tools_available": tools_available,
        "scope": scope,
        "moodle_session": moodle_session,
        "results": {},
    }
    for spec_step in spec["steps"]:
        step = copy.deepcopy(spec_step)
        step["target"] = target
        step["status"] = "pending"
        step["dry_run_command"] = build_dry_run_command(plan, step)
        # Gating en la generación: herramientas que faltan y sesión
        # Moodle ausente se marcan ya, no se inventa su resultado.
        gate_ok, gate_reason = _generation_gate(step, context)
        if step["tool"] == "moodle_sqli" and not moodle_session:
            # Sin sesión no hay ni detección ni extracción: los dos
            # pasos Moodle quedan bloqueados (DESIGN.md §4.3).
            gate_ok, gate_reason = False, (
                "falta la sesión de Moodle (sesskey y cookie vigentes)")
        if (step["tool"] == "msf"
                and step["action"] in ("msf_check", "msf_run")
                and not confirmed):
            # Check y run son ejecución: sin la casilla marcada no
            # se ejecutan (DESIGN.md §4.4). La correlación es solo
            # lectura y no se bloquea.
            gate_ok, gate_reason = False, (
                "sin autorización confirmada: marca la casilla para "
                "ejecutar módulos Metasploit")
        if not gate_ok:
            if step["tool"] in ("moodle_sqli", "msf"):
                step["status"] = "blocked"
                step["blocked_reason"] = gate_reason
                plan["warnings"].append(
                    "paso %s bloqueado: %s" % (step["id"], gate_reason))
            else:
                step["status"] = "skipped_missing_dependency"
                step["blocked_reason"] = gate_reason
                plan["warnings"].append(
                    "paso %s saltado: %s" % (step["id"], gate_reason))
        plan["steps"].append(step)
    validate_plan_structure(plan)
    return plan


def _generation_gate(step, context):
    """Gating evaluable al generar el plan (sin resultados de pasos).

    Devuelve (True, "") o (False, motivo). Las precondiciones
    previous_step_ok y moodle_vulnerable no se evalúan aquí: dependen
    de la ejecución y las verifica el runner con check_preconditions.
    """
    for pre in step.get("preconditions") or []:
        kind = pre.get("type")
        if kind == "tool_present":
            if not (context.get("tools_available") or {}).get(pre.get("tool")):
                return False, "%s no está instalado" % pre.get("tool")
        elif kind == "scope":
            if context.get("scope") != pre.get("scope"):
                return False, "scope debe ser %s" % pre.get("scope")
        elif kind == "moodle_session":
            if not context.get("moodle_session"):
                return False, (
                    "falta la sesión de Moodle (sesskey y cookie vigentes)")
    return True, ""


# -- re-planificación ---------------------------------------------------


def replan(plan, results, context=None):
    """Ajusta un plan ante fallos, sin re-ejecutar lo ya hecho.

    ``results``: {step_id: {"status": ..., "result": {...}, ...}} con
    el estado conocido de cada paso. ``context`` (opcional): lo mismo
    que en check_preconditions — {"tools_available": {...},
    "moodle_session": bool}; sin él, las precondiciones de
    herramientas y de sesión Moodle se evalúan como no cumplidas.
    Devuelve un plan nuevo (copia) con los estados actualizados y
    ``replan_notes``.
    """
    new_plan = copy.deepcopy(plan)
    notes = []
    results = results or {}
    # Para evaluar precondiciones, un paso fallido con on_fail skip
    # cuenta como saltado: su fallo no detiene el plan (su estado
    # registrado sigue siendo "failed").
    step_by_id = {s["id"]: s for s in new_plan.get("steps") or []}
    eval_results = {}
    for step_id, result in results.items():
        eval_results[step_id] = result
        spec = step_by_id.get(step_id)
        if (result.get("status") == "failed" and spec is not None
                and spec.get("on_fail") == "skip"):
            eval_results[step_id] = dict(result, status="skipped")
    stopped = False
    for step in new_plan.get("steps") or []:
        step_id = step["id"]
        known = results.get(step_id)
        if known is not None:
            step["status"] = known.get("status", step["status"])
            if known.get("status") == "failed" and step.get("on_fail") == "stop":
                stopped = True
                notes.append(
                    "el paso %s falló y su on_fail es stop: el plan se detiene"
                    % step_id)
            elif known.get("status") == "failed":
                notes.append(
                    "el paso %s falló y su on_fail es skip: se continúa"
                    % step_id)
            continue
        if stopped:
            if step.get("status") not in (
                    "skipped", "skipped_missing_dependency", "blocked"):
                step["status"] = "skipped"
                step["blocked_reason"] = "stopped: un paso anterior falló"
            continue
        if step.get("status") in (
                "skipped_missing_dependency", "blocked"):
            continue
        # Paso pendiente: ¿siguen cumpliéndose sus precondiciones?
        # El llamador aporta el contexto real (herramientas, sesión);
        # sin él, tool_present y moodle_session se dan por no cumplidas.
        ctx = dict(context or {})
        ctx.setdefault("tools_available", {})
        ctx.setdefault("moodle_session", False)
        ctx["scope"] = new_plan.get("scope")
        ctx["results"] = eval_results
        ok, reason = check_preconditions(step, ctx)
        if not ok:
            step["status"] = "skipped"
            step["blocked_reason"] = reason
            notes.append(
                "el paso %s queda saltado: %s" % (step_id, reason))
    new_plan["replan_notes"] = notes
    return new_plan
