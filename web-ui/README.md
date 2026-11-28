# Backend interno de Pent3stX

`server.py` conserva la API local de Pent3stX para que `pentestx_gui.py` (Tkinter/ttk) coordine la evaluación. Ya no existe interfaz web: el proceso escucha exclusivamente en `127.0.0.1:8765`, sirve únicamente rutas `/api/*` y responde `404` JSON a `/` y a cualquier ruta no API.

La GUI inicia el backend como proceso hijo cuando no hay un servicio activo, verifica `/api/status` antes de habilitar acciones y solo termina el proceso que inició. Para diagnóstico manual, ejecuta `python3 web-ui/server.py` desde la raíz; no uses `0.0.0.0` ni publiques el puerto.

## Guardrails

- Validación de target por sintaxis y allowlist exacta del servidor. No resuelve DNS desde la verificación.
- Acciones, pipelines y perfiles allowlisted; las operaciones activas requieren `scope=active`.
- La ejecución PentestX requiere preview dry-run exitoso del comando exacto, casilla de autorización escrita y referencia usable en `scope.yaml`.
- Moodle se limita a `http://127.0.0.1:8080/moodle`; sus cookies y sesskey no se devuelven ni se persisten. No se extrae el hash de contraseña.
- Metasploit limita targets y `LHOST` a las reglas existentes; búsqueda/correlación son de lectura; `check`, `run` y parada de sesión requieren confirmación.
- No hay shell arbitraria, instalación implícita de herramientas ni acceso a archivos estáticos.

## API conservada

### Estado, planificación y sesiones

- `GET /api/status` — estado del backend, presencia de `pentestx.py` y raíz del repositorio.
- `POST /api/plan` — valida `{target, scope, actions[], pipeline_profile, confirm_written_authorization?}`; ejecuta solo el dry-run y devuelve comando exacto, stdout/stderr, código, manifiesto y sesión.
- `POST /api/execute` — `{confirm: true, confirm_written_authorization: true}`; ejecuta solo si el dry-run exacto fue aprobado y `scope.yaml` contiene referencia usable.
- `POST /api/stop` — solicita detener el proceso PentestX activo.
- `GET /api/sessions` — sesiones reales de `workspace/pentestx_sessions/`.
- `GET /api/findings?session=<nombre>` — findings de la sesión, con el límite aplicado por el servidor.

### Motor de planificación

- `GET /api/engine/goals` — catálogo de objetivos y pasos.
- `POST /api/engine/plan` — `{goal, target, scope, confirm_written_authorization?, moodle?, findings?}`; valida y prepara el plan en memoria, sin ejecutar.
- `POST /api/engine/run` — `{confirm: true, confirm_written_authorization: true}`; requiere un plan previo y autorización. Los pasos PentestX también requieren la referencia de `scope.yaml`.

### Moodle local

- `POST /api/tools/moodle-sqli/dry-run` — valida la solicitud local y presenta payloads sin enviar la prueba al servidor Moodle.
- `POST /api/tools/moodle-sqli/run` — `{confirm: true, confirm_written_authorization: true}`; usa la solicitud exacta del dry-run almacenada en memoria. Extrae solo `database()` y `username`.

### Metasploit

- `GET|POST /api/msf/status` — estado de conexión y capacidades.
- `POST /api/msf/search` y `GET /api/msf/modules` — búsqueda de módulos.
- `POST /api/msf/module-info` — detalle de módulo.
- `POST /api/msf/correlate` — correlación de findings, solo lectura.
- `POST /api/msf/plan` — valida módulo, opciones y acción `check` o `run`; no ejecuta.
- `POST /api/msf/check` y `/api/msf/run` — necesitan plan en memoria, `{confirm: true, confirm_written_authorization: true}` y acciones peligrosas habilitadas en `msfmcpd`.
- `GET /api/msf/sessions` — sesiones activas de Metasploit.
- `POST /api/msf/session/stop` — `{session_id, confirm: true, confirm_written_authorization: true}`.
- `GET /api/msf/hosts`, `/api/msf/services`, `/api/msf/vulns` y `/api/msf/result?uuid=<id>` — consultas de lectura.

La raíz del repositorio y los directorios de evidencia se determinan desde la ubicación del proyecto. El backend no recibe archivos del navegador ni publica el workspace.

## Pruebas locales sin tráfico a objetivos

Desde la raíz:

```bash
python3 -m py_compile web-ui/server.py
python3 -m unittest discover -s web-ui -p 'test_server.py' -v
python3 -m unittest discover -s web-ui/engine -p 'test_engine.py' -v
python3 -m unittest discover -s web-ui/tools -p 'test_moodle_sqli.py' -v
```

`test_server.py` prueba validaciones, construcción de comandos y que `/`/rutas estáticas respondan `404` JSON. Si PyYAML no está instalado, el parser alternativo acepta solo el subconjunto de configuración esperado y rechaza valores YAML malformados o no textuales como referencia de autorización.
