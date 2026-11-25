# Motor de planificación por reglas — Pent3stX (diseño v1)

> Estado: **diseño aprobado para construir la v1** (Robert: "primero el
> diseño, luego lo construimos"). Este documento es la especificación
> que implementa `web-ui/engine/engine.py`. Si el diseño cambia, cambia
> primero aquí.

## 1. Idea

El motor convierte un **cometido** (goal) + el **mapeo** que ya existe
(sesiones, findings, herramientas instaladas) en un **plan de pasos
ordenados**, sin ejecutar nada al generarlo. El plan se muestra, se
aprueba con el comando exacto (dry-run) y solo entonces se ejecuta
paso a paso, verificando la precondición de cada paso antes de
ejecutarlo. No hay LLM ni caja negra: cada decisión del motor es una
regla escrita en `engine.py`, auditable y testeable.

```
mapeo (sesiones/findings/herramientas) + goal + autorización
        │
        ▼
  generate_plan()  ──►  plan JSON (sin ejecutar nada)
        │
        ▼  (usuario revisa y confirma)
  run_plan()  ──►  paso a paso, con precondiciones,
                   dry-run por paso, evidencia por paso
```

## 2. Entradas

| Entrada | Origen | Obligatoria |
|---|---|---|
| `goal` | Usuario, en el diálogo del motor | Sí: `owasp_report`, `full_assessment` o `moodle_sqli_confirm` |
| `target` | Usuario / Config | Sí: solo allowlist (`contaia.site`, `127.0.0.1`) |
| `scope` | Usuario / Config | Sí: `passive` o `active` |
| `pipeline_profile` | Derivado del goal (ver §4) | No: el goal fija el pipeline |
| `confirm_written_authorization` | Usuario, casilla en el diálogo del motor | No: sin marcarla, el plan es una medición del scope ("sin autorización confirmada") |
| `mapping` | El servidor, en el momento de planificar | No (se calcula): `tools_available` (`nmap`, `ffuf`, `sqlmap` por `shutil.which`), sesiones existentes en `workspace/pentestx_sessions/`, nº de findings |
| Moodle (`base_url`, `sesskey`, `session_cookie`) | Usuario, solo para `moodle_sqli_confirm` | Solo para ese goal; vive solo en memoria del servidor |

## 3. Salida: formato del plan JSON

```json
{
  "goal": "owasp_report",
  "target": "contaia.site",
  "scope": "passive",
  "pipeline_profile": "with_owasp",
  "confirm_written_authorization": true,
  "authorization_note": "autorización confirmada por casilla, sin referencia en la interfaz",
  "warnings": [],
  "steps": [
    {
      "id": "passive",
      "action": "passive",
      "tool": "pentestx",
      "target": "contaia.site",
      "preconditions": [],
      "expected_evidence": "execution_manifest.json + findings_db.json de la sesión",
      "on_fail": "stop",
      "status": "pending",
      "note": "Clasifica el target sin resolverlo ni contactarlo.",
      "dry_run_command": ["python3", "pentestx.py", "--target", "contaia.site",
        "--scope", "passive", "--action", "passive",
        "--pipeline-profile", "with_owasp",
        "--confirm-written-authorization",
        "--scope-file", "scope.yaml",
        "--dry-run"]
    }
  ]
}
```

Campos de cada paso:

- `id`: único dentro del plan; es el nombre del paso.
- `action`: acción de la allowlist del servidor (`passive`, `active`,
  `web`, `ports`, `vuln`, `owasp_web`, `vulnerability`, `correlate`,
  `report`) o `moodle_detect` / `moodle_extract` (herramienta aparte).
- `tool`: `pentestx` (CLI) o `moodle_sqli` (`web-ui/tools/`).
- `target`: el target de ese paso.
- `preconditions`: lista de precondiciones, cada una
  `{"type": ..., ...}` (ver §5). Un paso nunca se ejecuta si alguna
  precondición no se cumple.
- `expected_evidence`: qué debe existir tras el paso para darlo por
  bueno (manifiesto, findings, resultado `vulnerable`…).
- `on_fail`: `stop` (detener el plan; los pasos restantes quedan
  `skipped`) o `skip` (marcar el paso `skipped` y continuar).
- `status`: `pending` | `running` | `completed` | `failed` |
  `skipped` | `skipped_missing_dependency` | `blocked`.
- `dry_run_command`: comando exacto del dry-run de ese paso. En los
  pasos Moodle la sesskey y la cookie aparecen como
  `<sesskey-redacted>` / `<session-cookie-redacted>`; el comando real
  solo vive en memoria del servidor.

Límites: máximo **12 pasos** por plan; un goal desconocido se rechaza
con error; un target fuera de la allowlist se rechaza con error.

## 4. Goals y reglas v1

### 4.1 `owasp_report` — pipeline `with_owasp`, scope `passive`

| # | Paso | Tool | Precondición | on_fail |
|---|---|---|---|---|
| 1 | `passive` | pentestx | — | stop |
| 2 | `owasp_web` | pentestx | paso anterior OK | stop |
| 3 | `vulnerability` | pentestx | paso anterior OK | skip |
| 4 | `correlate` | pentestx | paso anterior OK | skip |
| 5 | `report` | pentestx | paso anterior OK | stop |

No necesita ninguna herramienta externa: el escaneo OWASP web es el
comprobador propio con `urllib` de la stdlib.

### 4.2 `full_assessment` — pipeline `full_web`, scope `active`

| # | Paso | Tool | Precondición | on_fail |
|---|---|---|---|---|
| 1 | `passive` | pentestx | — | stop |
| 2 | `active` | pentestx | `nmap` presente; scope `active` | skip |
| 3 | `intrusive` | pentestx | `nmap` presente; scope `active` | skip |
| 4 | `owasp_web` | pentestx | — | stop |
| 5 | `vulnerability` | pentestx | paso anterior OK | skip |
| 6 | `correlate` | pentestx | paso anterior OK | skip |
| 7 | `report` | pentestx | paso anterior OK | stop |

Regla de gating: si `nmap` no está instalado, los pasos `active` e
`intrusive` se generan con estado `skipped_missing_dependency` y un
warning en el plan; el resto del plan continúa y **nunca se inventa**
el resultado de esos pasos. Si `scope` no es `active`, generar el
plan es un error (las acciones activas exigen scope activo, como en
el resto del servidor).

### 4.3 `moodle_sqli_confirm` — pipeline `with_owasp`, scope `passive`, target `127.0.0.1`

| # | Paso | Tool | Precondición | on_fail |
|---|---|---|---|---|
| 1 | `passive` | pentestx | — | stop |
| 2 | `moodle_detect` | moodle_sqli | sesión Moodle aportada | stop |
| 3 | `moodle_extract` | moodle_sqli | detección `vulnerable == true` | stop |
| 4 | `correlate` | pentestx | paso anterior OK | skip |
| 5 | `report` | pentestx | paso anterior OK | stop |

Reglas propias de Moodle:

- `base_url` debe ser exactamente `http://127.0.0.1:8080/moodle`.
- Si el usuario no aporta sesskey + cookie vigentes, los pasos
  `moodle_detect` y `moodle_extract` se generan con estado `blocked`
  y motivo claro, y `correlate`/`report` quedan `skipped` (el plan no
  avanza ahí; no se inventa una detección).
- `moodle_detect` ejecuta la herramienta con `--extract database
  --max-chars 1`: la sonda de detección (`SLEEP`) más un solo
  carácter, suficiente para confirmar la vulnerabilidad sin hacer
  una extracción completa. `moodle_extract` ejecuta la extracción
  acotada (`database` + `username`, `--max-chars 50`).
- **Nunca** se extrae `password`: la herramienta lo rechaza y el
  motor no lo pide.

## 5. Precondiciones

Tipos (todos evaluables sin red, a partir de los resultados de los
pasos anteriores y del mapeo):

- `{"type": "tool_present", "tool": "nmap"}` — la herramienta está
  instalada (`shutil.which`).
- `{"type": "previous_step_ok", "step": "<id>"}` — el paso indicado
  terminó `completed`.
- `{"type": "previous_step_ok_or_skipped", "step": "<id>"}` — el paso
  indicado terminó `completed` o `skipped` (para encadenar tras un
  paso cuyo `on_fail` es `skip`: saltarlo no detiene el plan, pero un
  paso `blocked` o `failed` sí lo detiene).
- **Aún no decidible:** una precondición sobre un paso sin resultado
  todavía se da por cumplida al planificar; el runner la vuelve a
  comprobar justo antes de ejecutar el paso, cuando el resultado ya
  existe. Y un paso fallido con `on_fail: skip` cuenta como saltado
  para las precondiciones de los pasos siguientes (su estado
  registrado sigue siendo `failed`).
- `{"type": "moodle_session"}` — hay sesskey + cookie en memoria.
- `{"type": "moodle_vulnerable"}` — la detección devolvió
  `vulnerable == true`.
- `{"type": "scope", "scope": "active"}` — el scope del plan es ese.

## 6. Re-planificación — `replan(plan, results)`

Ante un paso fallido o una precondición no cumplida, `replan` devuelve
un plan ajustado **sin re-ejecutar lo ya hecho**:

1. Los pasos con resultado `completed` se conservan tal cual.
2. Un paso pendiente cuya precondición ya no se cumple se marca
   `skipped` con el motivo.
3. Si un paso falló con `on_fail: stop`, todos los pasos restantes
   quedan `skipped` con motivo `stopped: <id> falló`.
4. Si falló con `on_fail: skip`, el plan continúa con el siguiente
   paso cuya precondición se cumpla.
5. El resultado incluye `replan_notes`: lista de decisiones tomadas
   y por qué, para que quede en la evidencia.

`replan` es una función pura (no toca red ni disco): el runner la
aplica entre pasos y también se puede llamar a mano sobre un plan
guardado.

## 7. Guardrails (heredados del servidor + propios del motor)

- Allowlist de targets: solo `contaia.site` y `127.0.0.1`
  (y `http://127.0.0.1:8080/moodle` solo para los pasos Moodle).
- Autorización escrita obligatoria: la ejecución exige la casilla
  marcada ("Confirmo que tengo autorización escrita para este
  alcance") en el diálogo de confirmación y el mismo plan aprobado
  (hash del plan) con `confirm: true`. Los pasos pentestx exigen
  además una referencia usable en `scope.yaml` (la CLI la toma de
  ahí; sin ella, 409). La interfaz ya no escribe ninguna referencia:
  ningún comando lleva `--authorization-reference`.
- Acciones y pipelines solo de las allowlists existentes; sin RCE,
  sin escalada de privilegios, sin escritura en la BD, sin
  herramientas fuera de la allowlist (`nmap`, `ffuf`, `sqlmap` vía
  los perfiles ya controlados; el motor no añade herramientas).
- Cada paso pentestx hace su propio dry-run del comando exacto antes
  de ejecutarse (misma disciplina que `/api/plan` → `/api/execute`).
- La sesskey y la cookie de Moodle nunca se guardan en disco ni en
  logs: en la evidencia solo su SHA-256 + longitud, como en
  `moodle_sqli.py`.
- El motor no decide targets nuevos ni amplía el alcance: si el
  mapeo sugiere algo fuera de la allowlist, se ignora y se anota
  como warning.

## 8. API del backend (en `web-ui/server.py`)

- `GET /api/engine/goals` — los 3 goals con descripción, requisitos
  (herramientas, scope, sesión Moodle) y el esquema de pasos.
- `POST /api/engine/plan` — `{goal, target, scope,
  confirm_written_authorization?, moodle?: {base_url, sesskey,
  session_cookie, extract?}}`. Valida y devuelve el plan generado
  **sin ejecutar nada**. La respuesta nunca trae la sesskey ni la
  cookie. El plan aprobado queda guardado en memoria del servidor.
  Sin la casilla marcada, el plan dice "sin autorización confirmada"
  y sirve como medición del scope.
- `POST /api/engine/run` — `{confirm: true,
  confirm_written_authorization}`. Solo con un plan aprobado y la
  casilla marcada; si no, 409 sin ejecutar. Los pasos pentestx
  exigen además una referencia usable en `scope.yaml`. Ejecuta el
  plan paso a paso, verificando precondiciones y aplicando `replan`
  entre pasos. Guarda el plan y los resultados por paso en
  `workspace/engine_runs/<timestamp>/plan.json` (con los secretos
  redactados) y devuelve `{run_id, goal, steps: [...], status}`.

## 9. Interfaz web (sin romper el diseño 1)

- Menú **Assessments → "Motor: generar plan"** (deshabilitado sin
  backend, sin simular nada).
- Diálogo del motor: goal (select), target, scope y la casilla de
  autorización ("Confirmo que tengo autorización escrita para este
  alcance"); los campos de Moodle (base-url, sesskey, cookie) solo
  se muestran si el goal es `moodle_sqli_confirm`.
- El plan generado se muestra paso a paso en **Plan Overview** (lista
  de pasos con su estado) y en la consola verde; un diálogo de
  confirmación muestra el resumen del plan antes de ejecutar.
- Durante la ejecución, la consola muestra el avance por paso y los
  pasos saltados/bloqueados con su motivo. **Pause** detiene el
  proceso en curso (`/api/stop`).

## 10. Archivos

| Archivo | Propósito |
|---|---|
| `web-ui/engine/engine.py` | Motor: reglas, `generate_plan`, `replan`, validación (solo stdlib) |
| `web-ui/engine/test_engine.py` | Tests unitarios del planificador (sin red ni `pentestx.py`) |
| `web-ui/engine/DESIGN.md` | Este diseño |
| `web-ui/server.py` | Endpoints `/api/engine/*` y ejecución paso a paso |
| `web-ui/app.js`, `web-ui/index.html` | Diálogo del motor, Plan Overview y consola por paso |

## 11. Tests

`web-ui/engine/test_engine.py` (unittest, sin red, sin ejecutar
`pentestx.py` ni el exploit):

- Un plan por goal, con sus pasos en orden y el pipeline correcto.
- Gating: `full_assessment` sin `nmap` marca `active`/`intrusive`
  como `skipped_missing_dependency` y continúa.
- `moodle_sqli_confirm` sin sesskey/cookie: pasos Moodle `blocked`.
- Goal desconocido y target fuera de la allowlist: rechazados.
- Límite de 12 pasos: un plan con más pasos se rechaza.
- `replan` ante un paso fallido con `on_fail: stop` y con
  `on_fail: skip`, y ante una precondición no cumplida.
- El plan generado nunca contiene la sesskey ni la cookie en claro
  (solo redacción en el comando de muestra).

## 12. Fases de construcción

- **v1 (esta):** las 3 goals de §4, ejecución paso a paso con
  dry-run por paso, `replan`, evidencia en `workspace/engine_runs/`,
  UI mínima (diálogo + Plan Overview + consola).
- **v2 (pendiente, no en esta tarea):** el planificador podrá usar
  los findings de sesiones anteriores como mapeo de entrada (por
  ejemplo, si una sesión anterior ya detectó Moodle, proponer
  `moodle_sqli_confirm`); reglas nuevas solo añadiendo entradas a
  `GOALS` y tests, sin tocar el runner. Queda fuera de v1: ejecución
  en paralelo, reintentos automáticos y cualquier acción fuera de
  las allowlists actuales.
