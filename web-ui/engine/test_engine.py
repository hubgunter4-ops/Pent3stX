"""Tests del motor de planificación por reglas (web-ui/engine).

Unittest, sin red, sin ejecutar pentestx.py ni el exploit Moodle:
el planificador solo trabaja con el goal, el target y un mapeo
simulado que se pasa como dict. La re-planificación se prueba con
resultados fabricados en memoria.
"""

import json
import sys
import unittest
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ENGINE_DIR))

import engine  # noqa: E402


def _plan(goal, mapping=None, moodle=None, **kw):
    args = {
        "goal": goal,
        "target": "contaia.site",
        "scope": "passive",
        "confirm_written_authorization": True,
    }
    args.update(kw)
    return engine.generate_plan(mapping=mapping, moodle=moodle, **args)


def _step_ids(plan):
    return [s["id"] for s in plan["steps"]]


def _step(plan, step_id):
    return next(s for s in plan["steps"] if s["id"] == step_id)


class TestGoals(unittest.TestCase):
    def test_list_goals(self):
        goals = engine.list_goals()
        self.assertEqual(
            {g["goal"] for g in goals},
            {"owasp_report", "full_assessment", "moodle_sqli_confirm",
             "msf_targeted"})
        for goal in goals:
            self.assertTrue(goal["description"])
            self.assertTrue(goal["steps"])

    def test_owasp_report_plan(self):
        plan = _plan("owasp_report")
        self.assertEqual(
            _step_ids(plan),
            ["passive", "owasp_web", "vulnerability", "correlate", "report"])
        self.assertEqual(plan["pipeline_profile"], "with_owasp")
        self.assertEqual(plan["scope"], "passive")
        self.assertEqual(plan["warnings"], [])
        for step in plan["steps"]:
            self.assertEqual(step["status"], "pending")
            self.assertEqual(step["tool"], "pentestx")
            self.assertIn("--dry-run", step["dry_run_command"])
            self.assertIn(step["action"], step["dry_run_command"])

    def test_full_assessment_plan(self):
        plan = _plan("full_assessment", scope="active",
                     mapping={"tools_available": {"nmap": True}})
        self.assertEqual(
            _step_ids(plan),
            ["passive", "active", "intrusive", "owasp_web",
             "vulnerability", "correlate", "report"])
        self.assertEqual(plan["pipeline_profile"], "full_web")
        self.assertEqual(plan["scope"], "active")
        self.assertEqual(plan["warnings"], [])

    def test_full_assessment_requires_active_scope(self):
        with self.assertRaises(engine.ValidationError):
            _plan("full_assessment", scope="passive")

    def test_unknown_goal_rejected(self):
        with self.assertRaises(engine.ValidationError):
            _plan("hack_everything")

    def test_target_outside_allowlist_rejected(self):
        with self.assertRaises(engine.ValidationError):
            _plan("owasp_report", target="example.com")
        with self.assertRaises(engine.ValidationError):
            _plan("owasp_report", target="192.168.1.1")

    def test_authorization_is_a_checkbox(self):
        # La autorización es una casilla, no un texto: sin marcarla
        # el plan es una medición del scope ("sin autorización
        # confirmada"); marcada, dice "autorización confirmada por
        # casilla, sin referencia en la interfaz". Los comandos de
        # muestra nunca llevan --authorization-reference: la CLI la
        # toma de scope.yaml.
        for confirmed in (None, False):
            plan = _plan("owasp_report",
                         confirm_written_authorization=confirmed)
            self.assertIs(plan["confirm_written_authorization"], False)
            self.assertEqual(plan["authorization_note"],
                             "sin autorización confirmada")
            for step in plan["steps"]:
                self.assertNotIn("--authorization-reference",
                                 step["dry_run_command"])
                self.assertIn("--confirm-written-authorization",
                              step["dry_run_command"])
        plan = _plan("owasp_report")
        self.assertIs(plan["confirm_written_authorization"], True)
        self.assertEqual(
            plan["authorization_note"],
            "autorización confirmada por casilla, sin referencia "
            "en la interfaz")
        self.assertIn("--confirm-written-authorization",
                      _step(plan, "passive")["dry_run_command"])
        self.assertNotIn("--authorization-reference",
                         _step(plan, "passive")["dry_run_command"])

    def test_confirmation_must_be_boolean(self):
        with self.assertRaises(engine.ValidationError):
            _plan("owasp_report", confirm_written_authorization="sí")
        with self.assertRaises(engine.ValidationError):
            _plan("owasp_report", confirm_written_authorization=1)

    def test_max_steps_enforced(self):
        plan = _plan("owasp_report")
        plan["steps"] = plan["steps"] * 3  # 15 pasos
        with self.assertRaises(engine.ValidationError):
            engine.validate_plan_structure(plan)


class TestNmapGating(unittest.TestCase):
    def test_missing_nmap_skips_active_steps(self):
        plan = _plan("full_assessment", scope="active",
                     mapping={"tools_available": {"nmap": False}})
        self.assertEqual(
            _step(plan, "active")["status"], "skipped_missing_dependency")
        self.assertEqual(
            _step(plan, "intrusive")["status"], "skipped_missing_dependency")
        # El resto del plan sigue pendiente: nunca se inventa el resultado.
        self.assertEqual(_step(plan, "owasp_web")["status"], "pending")
        self.assertEqual(_step(plan, "report")["status"], "pending")
        self.assertTrue(any("nmap" in w for w in plan["warnings"]))

    def test_nmap_present_keeps_active_steps(self):
        plan = _plan("full_assessment", scope="active",
                     mapping={"tools_available": {"nmap": True}})
        self.assertEqual(_step(plan, "active")["status"], "pending")
        self.assertEqual(_step(plan, "intrusive")["status"], "pending")


class TestMoodleGoal(unittest.TestCase):
    MOODLE = {
        "base_url": "http://127.0.0.1:8080/moodle",
        "sesskey_present": True,
        "cookie_present": True,
    }

    def test_moodle_plan_with_session(self):
        plan = _plan("moodle_sqli_confirm", target="127.0.0.1",
                     moodle=self.MOODLE)
        self.assertEqual(
            _step_ids(plan),
            ["passive", "moodle_detect", "moodle_extract",
             "correlate", "report"])
        self.assertEqual(_step(plan, "moodle_detect")["status"], "pending")
        self.assertEqual(_step(plan, "moodle_extract")["status"], "pending")
        # El comando de muestra nunca trae la sesión en claro:
        # solo los marcadores de redacción (el nombre del flag
        # --sesskey sí aparece, su valor no).
        # Nunca password: la palabra solo puede aparecer en la nota
        # ("nunca password"), jamás como valor de --extract.
        for step_id in ("moodle_detect", "moodle_extract"):
            cmd = _step(plan, step_id)["dry_run_command"]
            self.assertIn("<sesskey-redacted>", cmd)
            self.assertIn("<session-cookie-redacted>", cmd)
            self.assertNotIn("password", cmd)
        self.assertIn("<session-cookie-redacted>",
                      _step(plan, "moodle_detect")["dry_run_command"])
        # La detección usa un solo carácter; la extracción, el tope.
        self.assertIn("1", _step(plan, "moodle_detect")["dry_run_command"])
        self.assertIn("50", _step(plan, "moodle_extract")["dry_run_command"])

    def test_moodle_plan_blocked_without_session(self):
        plan = _plan("moodle_sqli_confirm", target="127.0.0.1")
        self.assertEqual(_step(plan, "moodle_detect")["status"], "blocked")
        self.assertEqual(_step(plan, "moodle_extract")["status"], "blocked")
        self.assertEqual(_step(plan, "correlate")["status"], "pending")
        self.assertTrue(any("Moodle" in w for w in plan["warnings"]))

    def test_moodle_plan_wrong_base_url_blocks(self):
        moodle = dict(self.MOODLE, base_url="http://127.0.0.1:8080/otro")
        plan = _plan("moodle_sqli_confirm", target="127.0.0.1",
                     moodle=moodle)
        self.assertEqual(_step(plan, "moodle_detect")["status"], "blocked")


class TestMsfTargetedGoal(unittest.TestCase):
    FINDINGS = [
        {"id": "CVE-2017-0144", "title": "MS17-010 SMB",
         "service": "smb", "port": 445},
    ]

    def _msf_plan(self, **kw):
        args = {
            "goal": "msf_targeted",
            "target": "127.0.0.1",
            "scope": "active",
            "confirm_written_authorization": True,
            "mapping": {"findings": self.FINDINGS},
        }
        args.update(kw)
        return engine.generate_plan(**args)

    def test_msf_targeted_plan_steps(self):
        plan = self._msf_plan()
        self.assertEqual(
            _step_ids(plan),
            ["mapping", "vulnerability", "correlate", "msf_correlate",
             "msf_check", "msf_run", "report"])
        self.assertEqual(plan["pipeline_profile"], "with_owasp")
        self.assertEqual(plan["scope"], "active")
        self.assertEqual(plan["msf_findings"], self.FINDINGS)
        self.assertEqual(_step(plan, "mapping")["tool"], "engine")
        self.assertEqual(_step(plan, "msf_correlate")["tool"], "msf")
        self.assertEqual(_step(plan, "msf_check")["tool"], "msf")
        self.assertEqual(_step(plan, "msf_run")["tool"], "msf")
        # Sin casilla en mano, todos pendientes; el comando de
        # muestra de los pasos MSF no inventa ningún módulo.
        for step_id in ("mapping", "msf_correlate", "msf_check",
                        "msf_run"):
            self.assertEqual(_step(plan, step_id)["status"], "pending")
        self.assertIn("candidato",
                      " ".join(_step(plan, "msf_check")["dry_run_command"]))
        self.assertNotIn("ms17_010",
                          " ".join(_step(plan, "msf_check")["dry_run_command"]))

    def test_msf_targeted_requires_active_scope(self):
        with self.assertRaises(engine.ValidationError):
            self._msf_plan(scope="passive")

    def test_msf_targeted_blocked_without_checkbox(self):
        # Sin la casilla marcada, check y run quedan blocked; la
        # correlación (solo lectura) y el mapeo siguen pendientes.
        plan = self._msf_plan(confirm_written_authorization=False)
        self.assertEqual(_step(plan, "mapping")["status"], "pending")
        self.assertEqual(
            _step(plan, "msf_correlate")["status"], "pending")
        self.assertEqual(_step(plan, "msf_check")["status"], "blocked")
        self.assertEqual(_step(plan, "msf_run")["status"], "blocked")
        self.assertIn("sin autorización confirmada",
                      _step(plan, "msf_check")["blocked_reason"])
        self.assertTrue(any("msf_check" in w for w in plan["warnings"]))

    def test_msf_candidates_precondition(self):
        step = {"preconditions": [{"type": "msf_candidates"}]}
        # Sin resultado de msf_correlate todavía: aún no decidible.
        ok, _ = engine.check_preconditions(step, {"results": {}})
        self.assertTrue(ok)
        # Con candidatos: cumplida.
        ok, _ = engine.check_preconditions(step, {"results": {
            "msf_correlate": {"status": "completed", "result": {
                "correlations": [{"finding": {"id": "CVE-2017-0144"},
                                  "modules": [{"name": "windows/smb/x",
                                               "type": "exploit",
                                               "rank": 1,
                                               "reason": "CVE"}]}]}}}})
        self.assertTrue(ok)
        # Sin candidatos: no cumplida.
        ok, reason = engine.check_preconditions(step, {"results": {
            "msf_correlate": {"status": "skipped", "result": {
                "correlations": [{"finding": {"id": "x"},
                                  "modules": []}]}}}})
        self.assertFalse(ok)
        self.assertIn("candidatos", reason)

    def test_msf_checked_precondition(self):
        step = {"preconditions": [{"type": "msf_checked"}]}
        ok, _ = engine.check_preconditions(step, {"results": {}})
        self.assertTrue(ok)
        ok, _ = engine.check_preconditions(step, {"results": {
            "msf_check": {"status": "completed"}}})
        self.assertTrue(ok)
        ok, reason = engine.check_preconditions(step, {"results": {
            "msf_check": {"status": "failed"}}})
        self.assertFalse(ok)
        self.assertIn("msf_check", reason)

    def test_replan_no_candidates_skips_check_and_run(self):
        plan = self._msf_plan()
        results = {
            "mapping": {"status": "completed"},
            "vulnerability": {"status": "completed"},
            "correlate": {"status": "completed"},
            "msf_correlate": {
                "status": "skipped",
                "result": {"correlations": [
                    {"finding": {"id": "CVE-2017-0144"},
                     "modules": []}]},
            },
        }
        new = engine.replan(plan, results,
                            context={"tools_available": {}})
        # Sin candidatos, check queda saltado; el reporte sigue
        # pendiente (su precondición acepta "skipped").
        self.assertEqual(_step(new, "msf_check")["status"], "skipped")
        self.assertIn("candidatos",
                      _step(new, "msf_check")["blocked_reason"])
        self.assertEqual(_step(new, "report")["status"], "pending")
        # En la siguiente re-planificación, con msf_check ya
        # registrado como saltado, msf_run también queda saltado
        # (su precondición msf_checked ya es decidible y falla).
        results["msf_check"] = {"status": "skipped"}
        new = engine.replan(new, results,
                            context={"tools_available": {}})
        self.assertEqual(_step(new, "msf_run")["status"], "skipped")
        self.assertEqual(_step(new, "report")["status"], "pending")

    def test_replan_with_candidates_keeps_check(self):
        plan = self._msf_plan()
        results = {
            "mapping": {"status": "completed"},
            "vulnerability": {"status": "completed"},
            "correlate": {"status": "completed"},
            "msf_correlate": {
                "status": "completed",
                "result": {"correlations": [
                    {"finding": {"id": "CVE-2017-0144"},
                     "modules": [{"name": "windows/smb/ms17_010",
                                  "type": "exploit", "rank": 1,
                                  "reason": "CVE"}]}]},
            },
        }
        new = engine.replan(plan, results,
                            context={"tools_available": {}})
        self.assertEqual(_step(new, "msf_check")["status"], "pending")
        self.assertEqual(_step(new, "msf_run")["status"], "pending")


class TestReplan(unittest.TestCase):
    def _results(self, plan, statuses):
        return {
            step_id: {"status": status}
            for step_id, status in statuses.items()
        }

    def test_replan_stop_halts_remaining(self):
        plan = _plan("owasp_report")
        results = self._results(plan, {
            "passive": "completed",
            "owasp_web": "failed",
        })
        new = engine.replan(plan, results,
                            context={"tools_available": {}})
        self.assertEqual(_step(new, "owasp_web")["status"], "failed")
        self.assertEqual(_step(new, "vulnerability")["status"], "skipped")
        self.assertEqual(_step(new, "correlate")["status"], "skipped")
        self.assertEqual(_step(new, "report")["status"], "skipped")
        self.assertTrue(new["replan_notes"])
        # Lo ya hecho no se re-ejecuta: passive sigue completed.
        self.assertEqual(_step(new, "passive")["status"], "completed")

    def test_replan_skip_continues(self):
        plan = _plan("owasp_report")
        results = self._results(plan, {
            "passive": "completed",
            "owasp_web": "completed",
            "vulnerability": "failed",
        })
        new = engine.replan(plan, results,
                            context={"tools_available": {}})
        # vulnerability tenía on_fail skip: correlate sigue pendiente
        # (su precondición acepta "skipped") y report también.
        self.assertEqual(_step(new, "vulnerability")["status"], "failed")
        self.assertEqual(_step(new, "correlate")["status"], "pending")
        self.assertEqual(_step(new, "report")["status"], "pending")

    def test_replan_skips_step_with_unmet_precondition(self):
        plan = _plan("moodle_sqli_confirm", target="127.0.0.1",
                     moodle={
                         "base_url": "http://127.0.0.1:8080/moodle",
                         "sesskey_present": True,
                         "cookie_present": True,
                     })
        # Detección no vulnerable: la extracción no debe correr.
        results = {
            "passive": {"status": "completed"},
            "moodle_detect": {
                "status": "completed",
                "result": {"vulnerable": False},
            },
        }
        new = engine.replan(plan, results,
                            context={"tools_available": {},
                                     "moodle_session": True})
        self.assertEqual(_step(new, "moodle_extract")["status"], "skipped")
        self.assertIn("vulnerabilidad",
                      _step(new, "moodle_extract")["blocked_reason"])

    def test_replan_never_reruns_completed_steps(self):
        plan = _plan("owasp_report")
        results = self._results(plan, {
            "passive": "completed",
            "owasp_web": "completed",
            "vulnerability": "completed",
            "correlate": "completed",
            "report": "completed",
        })
        new = engine.replan(plan, results,
                            context={"tools_available": {}})
        self.assertTrue(all(
            s["status"] == "completed" for s in new["steps"]))


class TestPreconditions(unittest.TestCase):
    def test_tool_present(self):
        step = {"preconditions": [{"type": "tool_present", "tool": "nmap"}]}
        ok, _ = engine.check_preconditions(
            step, {"tools_available": {"nmap": True}})
        self.assertTrue(ok)
        ok, reason = engine.check_preconditions(
            step, {"tools_available": {"nmap": False}})
        self.assertFalse(ok)
        self.assertIn("nmap", reason)

    def test_unknown_precondition_fails_closed(self):
        step = {"preconditions": [{"type": "hacer_magia"}]}
        ok, _ = engine.check_preconditions(step, {})
        self.assertFalse(ok)

    def test_plan_hash_is_stable(self):
        plan = _plan("owasp_report")
        self.assertEqual(engine.plan_hash(plan),
                         engine.plan_hash(engine.generate_plan(
                             goal="owasp_report", target="contaia.site",
                             scope="passive",
                             confirm_written_authorization=True)))


if __name__ == "__main__":
    unittest.main()
