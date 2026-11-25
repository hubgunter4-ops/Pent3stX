# PentestX autorizado

**Estación local para planificar, ejecutar y documentar evaluaciones de seguridad autorizadas.** El módulo legado está archivado en `archive/kk2_legacy.py` y nunca se ejecuta; PentestX añade una capa CLI con controles de alcance y autorización. La interfaz ya no es una GUI de escritorio basada en Tkinter/ttk: `pentestx_gui.py` fue eliminado del repositorio y la interfaz actual es una web funcional en `web-ui/` (Design Option 1, estilo Ettercap clásico), con un backend local (`web-ui/server.py`, solo stdlib) que ejecuta la CLI con sus guardrails. Se arranca con `python3 web-ui/server.py` desde la raíz del repo y se abre en http://127.0.0.1:8765/. Las instrucciones completas están en [`web-ui/README.md`](web-ui/README.md).

> **Uso obligatorio:** trabaja únicamente sobre activos propios o cubiertos por autorización escrita y reglas de compromiso vigentes. La confirmación de la interfaz no sustituye la autorización del propietario.

## Nivel 1 — reparación de seguridad (2026-11-13)

1. **Legado archivado:** `kk2_repaired.py` (Hydra con credenciales en texto plano, John/Hashcat, Metasploit con `exec(code)`, escaneos agresivos, exfiltración y borrado de logs) se movió a `archive/kk2_legacy.py` con aviso. `pentestx.py` no lo importa ni lo carga: `load_legacy()` lanza `RuntimeError` si algo intenta usarlo.
2. **Pipelines controlados:** `standard`/`with_intrusive`/`with_owasp`/`full_web` solo usan pasos controlados (passive local, active `nmap -sn --max-rate 5`, intrusive `nmap -sT -sV` acotado, OWASP web GET/HEAD con topes, vulnerability/correlate/report locales). No existe ningún paso que invoque el legado; el modo real sin perfil controlado se niega.
3. **Alcance con `scope.yaml`:** por defecto solo `contaia.site` y `127.0.0.1`. Se rechazan redes privadas, `169.254.169.254`, `0.0.0.0/0`, redes más amplias que /24, multicast y loopback distinto de `127.0.0.1`. Toda acción con target exige `--authorization-reference` (ruta o identificador del documento de autorización escrita).
4. **Dry-run en la GUI:** botón «Ver plan (dry-run)» que muestra el comando exacto y lo ejecuta en modo dry-run; la ejecución real se niega hasta haber revisado el plan para ese comando exacto.
5. **`ffuf_safe` practicable:** wordlist propia de 200 entradas (`wordlists/ffuf_safe_200.txt`) y `max_requests: 200` explícito; una wordlist mayor que el tope se rechaza.
6. **Evidencia protegida:** `workspace/` en `.gitignore`; los cuerpos de respuesta se guardan solo como extracto de 1.024 caracteres con SHA-256; credenciales redactadas en texto y en estructuras (`redact_text`/`redact_value`, incluido `Authorization: Bearer <token>`); el escaneo OWASP se detiene ante 429/403.
7. **Licencia, tests y CI:** licencia MIT (`LICENSE`), tests en `tests/` (`python3 -m unittest discover -s tests -v`, solo mocks y dry-run, sin herramientas externas) y CI en `.github/workflows/ci.yml`.

**Fuera del nivel 1:** la telemetría (`telemetry_sender.py` y el panel de la GUI) sigue sin cifrado ni autenticación — solo destinos de laboratorio y sin secretos en el código.

**Nota (2026-11-25):** la GUI de la que habla el punto 4 ya no existe; el dry-run y la ejecución con el comando exacto ahora se hacen desde la interfaz web (`web-ui/server.py`), que conserva esa misma regla.

## Vista general

La interfaz actual es la web funcional en `web-ui/` (Design Option 1, estilo Ettercap clásico). Su distribución es: barra de título, menú File | Edit | View | Tools | Assessments | Plugins | Window | Help, barra de herramientas New, Open, Start, Pause, Scan, Import, Export, Save y Config con el distintivo «Authorized • Assessment Only», árbol **OPERATIONS • PHASES** a la izquierda, **Session Map** y **Plan Overview** al centro con la tabla de tareas, **Inspector** a la derecha con las pestañas Pipeline, Profiles y Findings, y la consola **TERMINAL CONSOLE** fija abajo con texto verde y las barras de estado.

La página no simula nada: con el backend local corriendo, Start hace primero un dry-run real con la CLI, muestra el comando exacto y solo ejecuta tras confirmación explícita; la consola muestra la salida real y el Inspector los findings reales de la sesión. Sin backend, Start queda deshabilitado. Las instrucciones completas están en [`web-ui/README.md`](web-ui/README.md). Nota: el GIF de ejecución (`web-ui/docs/ejecucion.gif`) es la animación antigua de la versión demo y ya no se incrusta en la guía; además todavía no está subido al repositorio.

Aparte, en `web-ui/tools/` vive la sonda Moodle SQLi local (CVE-2021-36393) como script separado: solo habla con el Moodle propio en `http://127.0.0.1:8080/moodle`, con dry-run y confirmación propios, y extrae únicamente `database()` y `username` (el hash de password quedó fuera a propósito). No toca `pentestx.py`; ver [`web-ui/tools/README.md`](web-ui/tools/README.md).

## Inicio rápido

### Dependencias

En Kali Linux o una distribución Debian/Ubuntu instala Python y las herramientas básicas:

```bash
sudo apt update
sudo apt install -y python3 coreutils
```

PyYAML es opcional y solo se necesita para políticas YAML:

```bash
python3 -m pip install -r requirements.txt
```

### Abrir la interfaz web

Arranca el backend local desde la raíz del repositorio (solo stdlib, sin dependencias nuevas) y abre la URL en el navegador:

```bash
python3 web-ui/server.py
# http://127.0.0.1:8765/ — solo local, Ctrl+C para detenerlo
```

El servidor valida cada petición (allowlist de targets, autorización obligatoria, acciones y pipelines permitidos) y ejecuta la CLI. La interfaz muestra el plan, la salida real y los findings reales. Sin el servidor corriendo, la página no simula nada y Start queda deshabilitado.

### Abrir la CLI

```bash
python3 pentestx.py --help
python3 pentestx.py --interactive
```

La CLI muestra el plan y solicita autorización y confirmación antes de ejecutar una operación.

## Tutorial paso a paso

### 1. Preparar el alcance

Antes de ejecutar nada, define el alcance autorizado: una IP, dominio, URL o red CIDR que esté dentro del alcance autorizado. En Config de la interfaz web pon el target, el scope, el pipeline y la referencia de autorización escrita; el backend valida el alcance (solo `contaia.site` y `127.0.0.1`) y rechaza cualquier otro target. Marca **Autorización escrita** solo cuando la autorización exista y cubra el target. Para fases activas, selecciona `active` en el alcance operativo. Las acciones activas no pueden ejecutarse con `scope=passive`.

### 2. Seleccionar fases

En el árbol **OPERATIONS • PHASES** de la interfaz web, pulsa las fases necesarias. La tabla **PLAN OVERVIEW** permite revisar el modo de cada fase antes de iniciar:

| Grupo | Fases disponibles |
|---|---|
| Reconocimiento | `passive`, `active` |
| Enumeración y revisión | `web`, `ports`, `vuln`, `owasp_web`, `vulnerability` |
| Correlación y salida | `correlate`, `report`, `correlated` |
| Perfiles controlados | `tool`, `intrusive` |

Las acciones `tool` requieren perfiles allowlisted. El escaneo `intrusive` usa perfiles limitados, puertos, tasa, timeout y exclusiones validadas por la CLI.

### 3. Revisar el Inspector y la consola

En la interfaz web, el **Inspector** de la derecha muestra el estado del pipeline (Pipeline Status), los perfiles activos (Profiles) y los findings reales de la sesión (Findings). La **TERMINAL CONSOLE** fija de abajo muestra en verde la salida real de la CLI. **Start** hace primero un dry-run real y muestra el comando exacto; tras tu confirmación ejecuta ese comando, y **Pause** detiene el proceso en curso. Session Map y la tabla de tareas parten en "Sin sesión" hasta que haya una sesión real.

### 4. Validar un plan con la CLI

Para generar un manifiesto sin tráfico, usa la CLI:

```bash
python3 pentestx.py \
  --target example.com \
  --scope passive \
  --action passive correlate report \
  --confirm-written-authorization \
  --dry-run
```

El resultado esperado incluye `DRY-RUN: no se ejecutarán funciones ni tráfico de red.` y un `execution_manifest.json` bajo `workspace/pentestx_sessions/<timestamp>/`.

### 5. Ejecutar un plan autorizado

Para ejecutar, revisa el plan, el target, el scope, los puertos, las exclusiones y la autorización; después pulsa **Start** en la interfaz web: primero verás el dry-run con el comando exacto y solo tras confirmarlo se ejecuta ese comando. La CLI también exige `--scope active` y `--confirm-written-authorization` para las acciones activas.

Ejemplo de previsualización de un pipeline controlado:

```bash
python3 pentestx.py \
  --target 192.0.2.10 \
  --scope active \
  --action correlated \
  --pipeline-profile with_intrusive \
  --intrusive-profile auto \
  --confirm-written-authorization \
  --dry-run
```

### 6. Telemetría

La nueva interfaz web no incluye panel de telemetría. El módulo `telemetry_sender.py` sigue en el repositorio, sin panel. Sigue sin cifrado ni autenticación, solo para destinos de laboratorio y sin secretos en el código. UDP no cifra ni confirma que la aplicación remota haya procesado el datagrama. Usa solo receptores controlados y prefiere HTTPS cuando esté disponible.

## Seguridad y límites

PentestX no expone desde su capa CLI ni desde la interfaz web funciones de fuerza bruta, explotación personalizada, post-explotación, persistencia en el target, pivoting o exfiltración. La fase `vulnerability` procesa findings existentes y produce candidatos para revisión manual; no autoriza explotación. Aparte de la CLI, `web-ui/tools/moodle_sqli.py` es una herramienta separada para el Moodle local del laboratorio (CVE-2021-36393), con sus propios guardrails (solo 127.0.0.1:8080/moodle, dry-run, autorización escrita y sin extracción del hash de password); no forma parte de los pipelines de `pentestx.py`.

La interfaz web ya no es de solo lectura ni simulación: ejecuta la CLI real a través del backend local, pero solo con dry-run previo del comando exacto, autorización escrita y los guardrails de la CLI (allowlist, pipelines controlados, sin shell). La ejecución real sigue viviendo en `pentestx.py` y solo corre en la máquina local donde se arranca el servidor.

La persistencia de la aplicación se limita a evidencia local, logs, manifiestos, capturas hashadas y reportes del workspace. No se crea persistencia en los activos evaluados.

## CLI, perfiles y políticas

Lista los perfiles fijos y personalizados:

```bash
python3 pentestx.py --list-profiles
python3 pentestx.py --policy-file profiles.example.yaml --list-profiles
```

Los perfiles fijos `ffuf_safe` y `sqlmap_safe` usan allowlists, límites de tasa, concurrencia, timeout, reintentos y categorías de findings compatibles. La instalación de herramientas está separada de la ejecución y permite únicamente paquetes allowlisted:

```bash
python3 pentestx.py \
  --profile ffuf_safe \
  --install-tools \
  --confirm-tool-install
```

La política OWASP web está documentada en [`OWASP_WEB_FINDINGS_PIPELINES.md`](OWASP_WEB_FINDINGS_PIPELINES.md). Los ejemplos se encuentran en [`profiles.example.yaml`](profiles.example.yaml) y [`owasp_profiles.example.yaml`](owasp_profiles.example.yaml).

## Salidas y evidencia

Cada sesión genera un workspace local. Según las fases seleccionadas puede contener `execution_manifest.json`, `findings_db.json`, `attack_chains.json`, logs por módulo, reportes, `vulnerability_review.json`, `VULNERABILITY_REVIEW.md`, manifiestos de perfiles, artefactos de escaneo intrusivo y capturas con SHA-256.

La guía de la interfaz actual está en [`web-ui/README.md`](web-ui/README.md). `GUI_TUTORIAL.md` describe la GUI de Tkinter eliminada y ya no está vigente como tutorial; las capturas en `docs/screenshots/` muestran los paneles antiguos de esa GUI.

## Comprobación y desarrollo

Ejecuta las comprobaciones básicas:

```bash
python3 -m py_compile telemetry_sender.py pentestx.py pentestx_controlled.py
python3 -m py_compile web-ui/server.py
python3 -m py_compile web-ui/tools/moodle_sqli.py
node --check web-ui/app.js
python3 -m unittest discover -s web-ui -p "test_server.py" -v
python3 -m unittest discover -s web-ui/tools -p "test_moodle_sqli.py" -v
python3 -m unittest discover -s tests -v
python3 pentestx.py --check-tools
# Dry-run contra contaia.site (requiere scope.yaml y referencia de autorización;
# copia scope.example.yaml a scope.yaml y completa la referencia):
python3 pentestx.py --target https://contaia.site \
  --scope active \
  --action correlated \
  --pipeline-profile standard \
  --confirm-written-authorization \
  --authorization-reference docs/AUTORIZACION-contaia.md \
  --scope-file scope.yaml \
  --dry-run
```

La validación histórica y la matriz de pruebas están en [`VALIDATION.md`](VALIDATION.md).

## Estructura del proyecto

| Archivo o directorio | Propósito |
|---|---|
| `web-ui/` | Interfaz web funcional (Design Option 1, estilo Ettercap clásico): `index.html`, `styles.css`, `app.js`, `server.py` (backend local), `test_server.py` y `README.md` con las instrucciones de uso. En `web-ui/tools/` vive aparte la sonda Moodle SQLi local (`moodle_sqli.py`, `test_moodle_sqli.py`, `README.md`). |
| `telemetry_sender.py` | Emisor asíncrono HTTP/UDP integrado desde el repo de telemetría. |
| `pentestx.py` | Capa CLI, validaciones, límites, pipelines y manifiestos. |
| `pentestx_controlled.py` | Alcance (`Scope`/`scope.yaml`), sesiones, pasos controlados y redacción de evidencia. |
| `archive/kk2_legacy.py` | Módulo legado archivado; nunca se ejecuta. |
| `scope.example.yaml` | Alcance de ejemplo (copiar a `scope.yaml`). |
| `wordlists/ffuf_safe_200.txt` | Wordlist de 200 entradas para el perfil `ffuf_safe`. |
| `tests/` | Tests automatizados de nivel 1 (unittest, mocks y dry-run). |
| `.github/workflows/ci.yml` | CI: compila los módulos y corre los tests. |
| `GUI_TUTORIAL.md` | Tutorial de la GUI de Tkinter eliminada; ya no está vigente. |
| `docs/screenshots/` | Capturas de los paneles antiguos de la GUI eliminada. |
| `workspace/` | Evidencia y sesiones generadas localmente. |

## Estado y licencia

El proyecto es experimental y está orientado a laboratorios y activos autorizados. Revisa [`CHANGELOG.md`](CHANGELOG.md), [`SECURITY.md`](SECURITY.md) y las reglas de compromiso antes de usarlo. Licencia MIT, ver [`LICENSE`](LICENSE).

Repositorio: [hubgunter4-ops/n](https://github.com/hubgunter4-ops/n)
