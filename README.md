# Pent3stX

Estación local para planificar, ejecutar y documentar evaluaciones de seguridad autorizadas, con interfaz web y backend local. Solo para activos propios o cubiertos por autorización escrita.

> **Vídeo:** [web-ui/docs/ejecucion.mp4](web-ui/docs/ejecucion.mp4) — demo de la interfaz ejecutando un plan, con backend simulado (mock de `pentestx.py`). La ejecución real solo se puede grabar en la máquina de laboratorio.

## Requisitos

- **Python 3** (la interfaz web y el backend usan solo la librería estándar, sin dependencias nuevas).
- **Opcionales, según lo que uses:**
  - `nmap`, `ffuf`, `sqlmap`, `traceroute` — solo los necesitan las fases activas/intrusivas y el perfil `tool`. El pipeline por defecto (`with_owasp`) no necesita ninguna herramienta externa, solo Python 3.
  - `python3-yaml` — solo para políticas YAML (`--policy-file`).
  - **Metasploit + `msfmcpd`** — solo para el panel de Metasploit.
- Comprueba qué tienes instalado con `python3 pentestx.py --check-tools`.

## Instalación

```bash
git clone https://github.com/hubgunter4-ops/Pent3stX.git
cd Pent3stX
```

Para actualizar a la última versión:

```bash
git pull origin main
git log --oneline -1
```

> Nota: existe un `pentestx_1.0_all.deb` (v1), pero está desactualizado: no incluye la herramienta Moodle, el motor, el panel de Metasploit ni la correlación. Usa `git clone` / `git pull`.

## Arranque

Desde la raíz del repositorio:

```bash
python3 web-ui/server.py
```

Abre http://127.0.0.1:8765/ en el navegador. El servidor solo escucha en `127.0.0.1` (solo esta máquina). Para detenerlo, Ctrl+C en la terminal.

**No abras `web-ui/index.html` con doble clic:** la página carga, pero con `file://` el navegador bloquea las llamadas al backend, la consola avisa "Backend no conectado" y Start queda deshabilitado.

## scope.yaml y autorización

La CLI exige una referencia de autorización escrita, también para el dry-run. La referencia vive en `scope.yaml`, no en la interfaz:

```bash
cp scope.example.yaml scope.yaml
```

Completa `authorization_reference` en `scope.yaml` con tu referencia. Sin una referencia usable ahí, el plan y el dry-run funcionan como medición del scope, pero la ejecución se rechaza con 409.

La autorización en la interfaz es solo una casilla por ejecución: **"Confirmo que tengo autorización escrita para este alcance"**, en el diálogo de confirmación. Sin marcarla, no se ejecuta nada. Marca la casilla solo cuando la autorización exista y cubra el target.

Targets permitidos: solo tu objetivo autorizado y `127.0.0.1` (localhost). Cualquier otro target se rechaza.

## Uso

### 1. Configura el objetivo

En **Config**: target (tu objetivo autorizado, por ejemplo `127.0.0.1`), scope (`passive` o `active`) y pipeline (`with_owasp` por defecto). Ese target es el objetivo fijado que comparten Start, el motor, Moodle y Metasploit.

### 2. Ejecuta un plan (Start)

1. Elige la fase en el árbol **OPERATIONS • PHASES** (`owasp_web` está seleccionada por defecto).
2. Pulsa **Start**. El backend hace primero un dry-run real con la CLI y muestra el comando exacto y el manifiesto en la consola verde. No se ejecuta nada todavía.
3. En el diálogo de confirmación revisa el comando exacto, marca la casilla **"Confirmo que tengo autorización escrita para este alcance"** y confirma. Solo entonces se ejecuta ese comando, sin cambios.
4. Sigue la salida real en la consola verde. **Pause** (o **Stop**) detiene el proceso en curso.
5. Revisa los **Findings** en el Inspector: son los de `findings_db.json` de la sesión real. Las sesiones quedan en `workspace/pentestx_sessions/<timestamp>/` (`execution_manifest.json`, `findings_db.json`).
6. **Export** descarga el reporte con la sesión, el comando del plan y los findings reales.

### 3. Motor de planificación

Menú **Assessments → Motor: generar plan**. Genera un plan de pasos ordenados sin ejecutar nada; tras confirmarlo se ejecuta paso a paso, con dry-run por paso y precondiciones. Goals:

- `owasp_report` — pasiva → OWASP web → vulnerabilidad → correlación → reporte.
- `full_assessment` — añade activa e intrusiva con nmap (sin nmap, esos pasos se saltan con aviso).
- `moodle_sqli_confirm` — detección Moodle y, si es vulnerable, extracción acotada de `database()` y `username`, nunca password.
- `msf_targeted` — mapeo → vulnerabilidad → correlación → correlación findings → módulos Metasploit → check y ejecución del módulo correlacionado, solo con casilla.

### 4. Moodle SQLi (local)

Menú **Tools → Moodle SQLi (local)**. Sonda de inyección SQL ciega por tiempo (CVE-2021-36393) contra tu Moodle propio en `http://127.0.0.1:8080/moodle`. Pega la sesskey y la cookie `MoodleSession` vigentes en el diálogo (caducan y no se guardan). Flujo igual que el resto: dry-run con los payloads exactos → confirmación con casilla → ejecución. Extrae solo `database()` y `username`; el hash de password quedó fuera a propósito. Detalles en [`web-ui/tools/README.md`](web-ui/tools/README.md).

### 5. Panel de Metasploit (local)

Menú **Tools → Metasploit (local)**. Necesita `msfmcpd` corriendo en tu PC:

```bash
msfrpcd -U msfuser -P <tu-password> -p 55553
./msfmcpd --mcp-transport http --enable-dangerous-actions
```

El panel se conecta a `http://127.0.0.1:3000/` (o lo que pongas en `MSF_MCP_URL`). Lectura sin casilla: buscar módulos, hosts, servicios, vulnerabilidades y sesiones. Check, ejecución y detener sesiones solo con la casilla marcada. Sin `--enable-dangerous-actions`, el panel solo lee.

**Correlación findings → módulos:** en el mismo diálogo, elige una sesión con findings (o pega findings en JSON) y pulsa **Correlacionar**. Devuelve por finding los módulos candidatos con rango y motivo (por CVE, por servicio y por puerto), con botón **Usar** que carga el módulo con el target ya fijado. También la usa el goal `msf_targeted` del motor.

**Payloads reverse:** al ejecutar un payload reverse, el panel arranca antes su handler `exploit/multi/handler` (LHOST `127.0.0.1`) por la misma conexión MCP y la sesión entrante se vincula a esa ejecución y aparece en la tabla de sesiones. Detalles en [`web-ui/msf/README.md`](web-ui/msf/README.md).

## Solución de problemas

**"No realiza ningún scan"** — comprueba en este orden:

1. **¿Abriste http://127.0.0.1:8765/?** Con doble clic en `web-ui/index.html` (`file://`) el backend no está conectado y Start queda deshabilitado.
2. **¿Está corriendo el servidor?** En la terminal debe verse `Pent3stX Workbench backend en http://127.0.0.1:8765/` y en la interfaz la barra verde debe decir "Backend conectado — pentestx.py disponible". Si no, arranca `python3 web-ui/server.py` desde la raíz del repo.
3. **¿Existe `scope.yaml` con referencia?** Sin referencia usable en `scope.yaml`, el plan es solo una medición del scope y la ejecución se rechaza. Copia `scope.example.yaml` y completa `authorization_reference`.
4. **¿Marcaste la casilla?** Sin marcar "Confirmo que tengo autorización escrita para este alcance" en el diálogo de confirmación, la ejecución se rechaza con 409.
5. **¿Qué dice la consola verde tras Start?** Ahí está el motivo exacto (dry-run rechazado, target fuera de la allowlist, falta de referencia, etc.).
6. **Diagnóstico rápido:**
   ```bash
   curl http://127.0.0.1:8765/api/status
   git log --oneline -1
   ls web-ui/server.py
   python3 pentestx.py --check-tools
   ```

La guía completa de la interfaz está en [`web-ui/README.md`](web-ui/README.md). Licencia MIT.
