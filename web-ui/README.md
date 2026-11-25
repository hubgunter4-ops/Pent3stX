# Pent3stX Workbench — interfaz web funcional (Design Option 1)

Interfaz web que reproduce el diseño 1 estilo Ettercap clásico elegido
por Robert. **Sustituye a la GUI original de Tkinter
(`pentestx_gui.py`), que fue eliminada del repositorio.** Ya no es una
demo: con el backend local corriendo, Start ejecuta de verdad la CLI
(`pentestx.py`) con sus guardrails; sin backend, la interfaz no simula
nada y lo dice.

> **Uso autorizado únicamente.** Solo para activos propios o cubiertos
> por autorización escrita y reglas de compromiso vigentes. La
> ejecución real solo acepta los targets permitidos y exige confirmar
> por casilla que existe autorización escrita para ese alcance; la
> referencia que pide la CLI vive en `scope.yaml` (copia
> `scope.example.yaml`) y nunca se escribe en la interfaz ni se
> guarda en el navegador.

## Cómo arrancar

Desde la raíz del repositorio:

```bash
python3 web-ui/server.py
```

Y abre http://127.0.0.1:8765/ en el navegador. El servidor solo
escucha en 127.0.0.1 (solo esta máquina), sirve los archivos de
`web-ui/` y expone la API que usa la página. Para detenerlo, Ctrl+C
en la terminal.

Sin dependencias nuevas: solo la librería estándar de Python 3. Si
abres `web-ui/index.html` directamente con doble clic, la página
carga pero el backend no está conectado: la consola lo indica y
Start queda deshabilitado. No hay modo simulación.

## Flujo: dry-run → confirmación → ejecución

1. **Configura** en Config (o con los valores por defecto): target
   `contaia.site`, scope `passive` y pipeline `with_owasp`. La
   autorización ya no es texto en ningún lado de la interfaz: es una
   casilla por ejecución ("Confirmo que tengo autorización escrita
   para este alcance") en el diálogo de confirmación. Sin marcarla,
   el plan y el dry-run funcionan como medición del scope y dicen
   explícitamente "sin autorización confirmada"; la ejecución se
   rechaza. La referencia que exige la CLI vive en `scope.yaml`
   (copia `scope.example.yaml`): la CLI la toma de ahí, y sin una
   referencia usable ahí la ejecución también se rechaza con 409,
   aunque la casilla esté marcada.
2. **Elige fase** en el árbol `OPERATIONS • PHASES` (por ejemplo
   `owasp_web`, seleccionada por defecto). La fase define las acciones
   que se pedirán a la CLI.
3. **Pulsa Start.** El backend hace primero un dry-run real con
   `pentestx.py --dry-run` y muestra en la consola el comando exacto
   y el manifiesto. No se ejecuta nada todavía.
4. **Confirma** en el diálogo el comando exacto. Solo entonces se
   ejecuta ese comando, sin cambios. Si cancelas, no se ejecuta nada.
5. **Sigue la consola verde**: muestra la salida real de la CLI.
   **Pause** detiene el proceso en curso.
6. **Revisa los Findings** en el Inspector: son los de
   `findings_db.json` de la sesión real, tal cual vienen; si la
   sesión no tiene findings, dice "Sin findings en esta sesión".
   **Session Map** y la tabla de tareas parten en "Sin sesión" hasta
   que haya una sesión real en `workspace/pentestx_sessions/`.
7. **Export** descarga el reporte con la sesión, el comando del plan
   y los findings reales. **Save** guarda solo la configuración
   (target, scope, pipeline) en el navegador.

## Guardrails (los aplica el servidor, no la página)

- **Allowlist exacta:** solo `contaia.site` y `127.0.0.1`. Se
  rechazan redes privadas, `169.254.169.254`, `0.0.0.0/0`, redes más
  amplias que /24, multicast y cualquier otro loopback. El target se
  valida solo por sintaxis, sin resolverlo ni contactar la red.
- **Autorización obligatoria:** la ejecución exige la casilla
  marcada ("Confirmo que tengo autorización escrita para este
  alcance") y una referencia usable en `scope.yaml` (la CLI la toma
  de ahí; sin ella, 409 con un mensaje claro). El plan y el dry-run
  sin casilla son solo una medición del scope y lo dicen
  explícitamente ("sin autorización confirmada").
- **Acciones y pipelines allowlisted:** acciones `passive`, `active`,
  `web`, `ports`, `vuln`, `owasp_web`, `vulnerability`, `correlate`,
  `report`, `correlated`; pipelines `standard`, `with_intrusive`,
  `with_owasp`, `full_web`. Las acciones activas y los pipelines con
  trabajo intrusivo exigen scope `active`.
- **Dry-run exacto:** la ejecución solo se permite si antes hubo un
  dry-run exitoso del comando exacto y con la casilla marcada; si
  no, el servidor responde 409 y no ejecuta nada.
- **Sin shell:** la CLI se ejecuta con `subprocess` sin shell, con
  una lista fija de argumentos. No hay `--install-tools`, ni perfiles
  personalizados, ni comandos arbitrarios, ni subida de archivos al
  servidor.
- **Solo local:** el backend solo escucha en 127.0.0.1, puerto 8765.

## API del backend

- `GET /api/status` — `{backend: "ok", pentestx_present: true|false}`.
- `POST /api/plan` — `{target, scope, actions[], pipeline_profile,
  confirm_written_authorization?}`. Devuelve el comando exacto, la
  salida, el exit code, el manifiesto y la sesión del dry-run. Sin
  la casilla marcada, el plan es una medición del scope: devuelve
  el plan con `authorization_note: "sin autorización confirmada"` y
  `needs_authorization: true` (la CLI exige una referencia en
  `scope.yaml` incluso para el dry-run). El comando exacto lleva
  siempre `--confirm-written-authorization` y nunca
  `--authorization-reference`: la referencia vive en `scope.yaml`.
- `POST /api/execute` — `{confirm: true,
  confirm_written_authorization}`. Solo con dry-run previo del
  comando exacto y la casilla marcada; sin casilla, 409. Además, sin
  una referencia usable en `scope.yaml`, 409 con "marca la casilla y
  pon la referencia en scope.yaml (copia scope.example.yaml) para
  ejecutar; sin ella solo se genera el plan como medición del scope".
  Devuelve salida, exit code, sesión y manifiesto.
- `POST /api/stop` — detiene el proceso en curso.
- `GET /api/sessions` — sesiones reales de
  `workspace/pentestx_sessions/`.
- `GET /api/findings?session=<nombre>` — findings de esa sesión,
  máximo 200, tal cual vienen de `findings_db.json`.
- `POST /api/tools/moodle-sqli/dry-run` — valida y devuelve los
  payloads exactos de la sonda Moodle SQLi sin enviar nada (la
  casilla no se necesita para el dry-run: es una medición).
- `POST /api/tools/moodle-sqli/run` — `{confirm: true,
  confirm_written_authorization}`. Solo con dry-run previo del
  comando exacto y la casilla marcada; sin casilla, 409 sin
  ejecutar. La sonda no usa `scope.yaml`: solo necesita la casilla.
- `GET /api/engine/goals` — los 3 goals del motor con descripción,
  requisitos y pasos.
- `POST /api/engine/plan` — `{goal, target, scope,
  confirm_written_authorization?, moodle?}`. Genera el plan sin
  ejecutar nada; lo deja aprobado en memoria del servidor. Sin la
  casilla marcada, el plan dice "sin autorización confirmada" y
  sirve como medición del scope.
- `POST /api/engine/run` — `{confirm: true,
  confirm_written_authorization}`. La ejecución exige la casilla
  marcada; sin ella, 409. Los pasos pentestx exigen además una
  referencia usable en `scope.yaml` (sin ella, 409 con el mensaje
  de scope.yaml); los pasos Moodle solo necesitan la casilla.
  Ejecuta el plan paso a paso (dry-run por paso, precondiciones,
  `replan`) y guarda la evidencia en
  `workspace/engine_runs/<timestamp>/plan.json`.
- `GET /api/msf/status` y `POST /api/msf/status` — conexión con
  el `msfmcpd` local (127.0.0.1:3000): `{connected,
  dangerous_actions, tools, handlers}`.
- `POST /api/msf/search`, `GET /api/msf/modules?type=&q=`,
  `POST /api/msf/module-info`, `GET /api/msf/hosts|services|vulns`,
  `GET /api/msf/sessions`, `GET /api/msf/result?uuid=` — lectura
  de Metasploit sin casilla (ver `web-ui/msf/README.md`).
- `POST /api/msf/plan` — `{type, name, action: check|run,
  options}`. Valida el módulo y sus opciones y devuelve el plan
  exacto; con payload reverse incluye el handler
  `exploit/multi/handler` que se arrancará antes. No ejecuta nada.
- `POST /api/msf/check` y `POST /api/msf/run` — `{confirm: true,
  confirm_written_authorization}`. Exigen plan aprobado y la
  casilla marcada; sin casilla, 409; con las acciones peligrosas
  de `msfmcpd` desactivadas, 409 con el mensaje de
  `--enable-dangerous-actions`. Evidencia en
  `workspace/msf_runs/<timestamp>/manifest.json`.
- `POST /api/msf/session/stop` — `{confirm: true,
  confirm_written_authorization, session_id}`. Detiene una
  sesión; también exige la casilla.

## Motor de planificación por reglas

Menú **Assessments → Motor: generar plan**: a partir del mapeo
(sesiones, findings, herramientas instaladas) genera un plan de
pasos ordenados para un goal, sin ejecutar nada. Los goals son
`owasp_report` (pasiva → OWASP web → vulnerabilidad → correlación
→ reporte), `full_assessment` (añade activa e intrusiva con nmap;
sin nmap esos pasos se saltan con aviso) y `moodle_sqli_confirm`
(detección Moodle y, si es vulnerable, extracción acotada de
`database()` y `username`, nunca password). El plan se muestra paso
a paso en **Plan Overview**; tras confirmarlo se ejecuta paso a
paso, con la salida real por paso en la consola verde. Diseño y
reglas en [`web-ui/engine/DESIGN.md`](engine/DESIGN.md); el motor
es `web-ui/engine/engine.py` (solo stdlib, determinista, sin LLM).

## Herramienta aparte: Moodle SQLi (local)

Menú **Tools → Moodle SQLi (local)**: sonda de inyección SQL ciega
por tiempo (CVE-2021-36393) contra el Moodle propio del laboratorio,
en `web-ui/tools/moodle_sqli.py` y documentada en
`web-ui/tools/README.md`. Solo habla con
`http://127.0.0.1:8080/moodle`, con la sesskey y la cookie
MoodleSession vigentes que pegues en el diálogo (caducan y no se
guardan). Flujo igual que el resto: dry-run con los payloads
exactos → confirmación → ejecución, con la salida real en la
consola verde. Extrae solo `database()` y `username`; **el hash de
password quedó fuera a propósito**. No toca `pentestx.py`: es un
script aparte con sus propios guardrails.

## Panel de Metasploit (local)

Menú **Tools → Metasploit (local)**: panel completo con exploits
sobre el MCP oficial de Metasploit (`msfmcpd`), en
`web-ui/msf/msf_client.py` y documentado en
`web-ui/msf/README.md`. Necesita `msfmcpd` corriendo en tu PC
(por defecto en `http://127.0.0.1:3000/`; arranca con
`./msfmcpd --mcp-transport http --enable-dangerous-actions`).
Lectura sin casilla (buscar módulos, ver sesiones); check, run y
detener sesiones solo con la casilla de autorización marcada.
Targets solo `contaia.site` y `127.0.0.1`; `LHOST` solo
`127.0.0.1`. Un payload reverse arranca antes su handler
`exploit/multi/handler` por la misma conexión MCP (el handler es
un job del framework, no hace falta una segunda conexión) y la
sesión entrante se vincula a esa ejecución y aparece en la tabla
de sesiones. Evidencia en `workspace/msf_runs/<timestamp>/`.

## Qué se ve en cada zona

- **Barra de título:** `Pent3stX Workbench — Design Option 1 —
  Authorized Security Assessment`.
- **Menú:** File, Edit, View, Tools, Assessments, Plugins, Window y
  Help.
- **Barra de herramientas:** New, Open, Start, Pause, Scan, Import,
  Export, Save y Config, con el distintivo `Authorized • Assessment
  Only` a la derecha.
- **OPERATIONS • PHASES (izquierda):** árbol de fases — `passive`
  (discovery, passive-recon), `active` (host-probe), `web` (crawl),
  `ports` (portscan), `vuln` (vuln-scan), `owasp_web` (owasp-zap,
  seleccionada por defecto), `correlate` (correlation) y `report`
  (generate-report).
- **Session Map (centro):** sin sesión al arrancar; tras una
  ejecución real muestra el nombre de la sesión y el target.
- **Plan Overview (centro):** el plan real aprobado por el dry-run.
- **Tabla de tareas (centro):** sin sesión al arrancar; tras una
  ejecución muestra la sesión real.
- **INSPECTOR (derecha):** pestañas Pipeline, Profiles y Findings.
  Pipeline muestra los pasos del plan real con su estado; Findings
  muestra los findings reales de la sesión.
- **TERMINAL CONSOLE (abajo, fija):** consola verde con la salida
  real. Debajo, la barra de estado del backend.
- **Barra de estado (pie):** sesión actual y backend local.

## Qué NO hace

- No ejecuta nada sin dry-run previo del comando exacto, sin la
  casilla de autorización marcada ni sin una referencia usable en
  `scope.yaml` (la casilla se marca al confirmar, por ejecución;
  nunca se guarda nada en el navegador).
- No acepta targets fuera de la allowlist ni acciones o pipelines
  fuera de las listas permitidas.
- No instala herramientas ni ejecuta comandos arbitrarios.
- No sustituye la autorización escrita: la confirmación en la
  interfaz no es autorización del propietario del activo.

## Archivos

- `web-ui/index.html` — estructura de la interfaz.
- `web-ui/styles.css` — estilos del diseño Ettercap clásico.
- `web-ui/app.js` — comportamiento funcional (llama a la API local,
  sin simulación).
- `web-ui/server.py` — backend local (solo stdlib, 127.0.0.1:8765).
- `web-ui/test_server.py` — tests unitarios de la validación del
  servidor (sin llamar a `pentestx.py`).
- `web-ui/engine/engine.py` — motor de planificación por reglas
  (goals `owasp_report`, `full_assessment` y `moodle_sqli_confirm`),
  con `web-ui/engine/test_engine.py` y `web-ui/engine/DESIGN.md`.
- `web-ui/tools/moodle_sqli.py` — sonda Moodle SQLi local aparte
  (CVE-2021-36393; solo database y username, sin password), con
  `web-ui/tools/test_moodle_sqli.py` y `web-ui/tools/README.md`.
- `web-ui/README.md` — esta guía.
- `web-ui/docs/ejecucion.gif` — animación antigua de la versión demo
  (solo maqueta de layout, no es una ejecución real; ya no se
  incrusta en esta guía).

## Comprobación (sin ejecutar pentestx.py)

```bash
python3 -m py_compile web-ui/server.py
python3 -m py_compile web-ui/tools/moodle_sqli.py
python3 -m py_compile web-ui/engine/engine.py
node --check web-ui/app.js
python3 -m unittest discover -s web-ui -p "test_server.py" -v
python3 -m unittest discover -s web-ui/tools -p "test_moodle_sqli.py" -v
python3 -m unittest discover -s web-ui/engine -p "test_engine.py" -v
```

La ejecución real solo se puede probar en la máquina de laboratorio
con su `scope.yaml` y su autorización, arrancando el servidor como se
indica arriba.
