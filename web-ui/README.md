# Pent3stX Workbench — interfaz web funcional (Design Option 1)

Interfaz web que reproduce el diseño 1 estilo Ettercap clásico elegido
por Robert. **Sustituye a la GUI original de Tkinter
(`pentestx_gui.py`), que fue eliminada del repositorio.** Ya no es una
demo: con el backend local corriendo, Start ejecuta de verdad la CLI
(`pentestx.py`) con sus guardrails; sin backend, la interfaz no simula
nada y lo dice.

> **Uso autorizado únicamente.** Solo para activos propios o cubiertos
> por autorización escrita y reglas de compromiso vigentes. La
> ejecución real solo acepta los targets permitidos y exige la
> referencia de autorización escrita.

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
   `contaia.site`, scope `passive`, pipeline `with_owasp` y la
   referencia de autorización escrita (por ejemplo
   `docs/AUTORIZACION-contaia.md`). Sin referencia no hay Start.
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
- **Autorización obligatoria:** sin `authorization_reference` no hay
  dry-run ni ejecución.
- **Acciones y pipelines allowlisted:** acciones `passive`, `active`,
  `web`, `ports`, `vuln`, `owasp_web`, `vulnerability`, `correlate`,
  `report`, `correlated`; pipelines `standard`, `with_intrusive`,
  `with_owasp`, `full_web`. Las acciones activas y los pipelines con
  trabajo intrusivo exigen scope `active`.
- **Dry-run exacto:** la ejecución solo se permite si antes hubo un
  dry-run exitoso del comando exacto y con la misma referencia de
  autorización; si no, el servidor responde 409 y no ejecuta nada.
- **Sin shell:** la CLI se ejecuta con `subprocess` sin shell, con
  una lista fija de argumentos. No hay `--install-tools`, ni perfiles
  personalizados, ni comandos arbitrarios, ni subida de archivos al
  servidor.
- **Solo local:** el backend solo escucha en 127.0.0.1, puerto 8765.

## API del backend

- `GET /api/status` — `{backend: "ok", pentestx_present: true|false}`.
- `POST /api/plan` — `{target, scope, actions[], pipeline_profile,
  authorization_reference}`. Devuelve el comando exacto, la salida,
  el exit code, el manifiesto y la sesión del dry-run.
- `POST /api/execute` — `{confirm: true, authorization_reference}`.
  Solo con dry-run previo del comando exacto. Devuelve salida, exit
  code, sesión y manifiesto.
- `POST /api/stop` — detiene el proceso en curso.
- `GET /api/sessions` — sesiones reales de
  `workspace/pentestx_sessions/`.
- `GET /api/findings?session=<nombre>` — findings de esa sesión,
  máximo 200, tal cual vienen de `findings_db.json`.
- `POST /api/tools/moodle-sqli/dry-run` — valida y devuelve los
  payloads exactos de la sonda Moodle SQLi sin enviar nada
  (requiere referencia de autorización).
- `POST /api/tools/moodle-sqli/run` — `{confirm: true,
  authorization_reference}`. Solo con dry-run previo del comando
  exacto y la misma referencia; si no, 409 sin ejecutar.

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

- No ejecuta nada sin dry-run previo del comando exacto ni sin
  referencia de autorización.
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
node --check web-ui/app.js
python3 -m unittest discover -s web-ui -p "test_server.py" -v
python3 -m unittest discover -s web-ui/tools -p "test_moodle_sqli.py" -v
```

La ejecución real solo se puede probar en la máquina de laboratorio
con su `scope.yaml` y su autorización, arrancando el servidor como se
indica arriba.
