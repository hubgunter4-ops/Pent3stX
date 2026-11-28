# Pent3stX

Estación local para planificar, ejecutar y documentar evaluaciones de seguridad autorizadas. La interfaz de escritorio usa **Tkinter/ttk** y se comunica con un backend HTTP interno limitado a `127.0.0.1:8765`; el backend ya no publica una web ni sirve archivos estáticos. Uso exclusivo sobre activos propios o cubiertos por autorización escrita vigente.

## Requisitos

- Python 3.10 o posterior.
- Tkinter para la versión de Python instalada. En Debian/Kali suele proporcionarlo `python3-tk`; si la GUI informa que falta, instálalo desde el gestor del sistema. Pent3stX no instala dependencias automáticamente y no necesita paquetes pip nuevos.
- Opcionales según las fases elegidas: `nmap`, `ffuf`, `sqlmap`, `traceroute`, `python3-yaml` para políticas YAML y Metasploit con `msfmcpd` para el panel local.

## Instalación

```bash
git clone https://github.com/hubgunter4-ops/Pent3stX.git
cd Pent3stX
```

## Arranque

Desde la raíz del repositorio:

```bash
python3 pentestx_gui.py
```

La GUI inicia su backend local, verifica que responda para este repositorio y mantiene la ventana receptiva mientras consulta el API. Si encuentra un backend en el puerto `8765`, solo lo usa si `/api/status` confirma identidad y raíz del mismo repositorio. Al cerrar, termina únicamente el proceso que inició la GUI. No se abre navegador: `GET /` y las rutas no API responden `404` JSON.

La configuración no sensible (target, scope y pipeline) se guarda con **Guardar** en `$XDG_CONFIG_HOME/pentestx/preferences.json` o, por defecto, `~/.config/pentestx/preferences.json`. Las cookies y sesskey de Moodle y el token de Metasploit se mantienen en memoria y no se guardan.

## Flujo de evaluación

1. Edita libremente **Target** y selecciona **Scope** (`passive` o `active`) y **Pipeline** (`standard`, `with_intrusive`, `with_owasp` o `full_web`). No hay autocompletado ni sugerencias de target. La validación autoritativa es del backend.
2. Selecciona una fase en `OPERATIONS • PHASES` y pulsa **Ver plan (dry-run)**. La GUI muestra el comando exacto, manifiesto, código de salida y resultado; todavía no ejecuta el plan.
3. Solo con un dry-run aprobado se habilita **Ejecutar**. Revisa el comando exacto, marca **“Confirmo que tengo autorización escrita para este alcance”** y confirma. El backend exige además una referencia usable en `scope.yaml`; la casilla no sustituye la autorización ni la referencia escrita.
4. **Pausar / detener** solicita `/api/stop` para la evaluación activa iniciada desde esta GUI. Revisa las sesiones y findings reales en `Session Map` e `Inspector → Findings`; exporta un JSON con **Exportar**.

La allowlist del backend es exacta y se valida por sintaxis, sin resolver DNS: `contaia.site` y `127.0.0.1` (con los formatos admitidos por el servidor). Las acciones activas y los pipelines con trabajo intrusivo requieren `scope=active`. No se admiten comandos arbitrarios ni `--install-tools` desde la GUI.

## Motor y herramientas locales

- **Evaluaciones → Motor: generar plan…** genera y presenta pasos sin ejecutar; la ejecución paso a paso exige confirmación escrita y conserva las precondiciones del backend.
- **Herramientas → Moodle SQLi (local)…** solo acepta el Moodle local fijo `http://127.0.0.1:8080/moodle`. Sesskey y cookie se enmascaran y son temporales. El flujo es dry-run de payloads → confirmación → ejecución; solo contempla `database()` y `username`, no el hash de contraseña.
- **Herramientas → Metasploit (local)…** ofrece estado, búsqueda y detalle de módulos, correlación de findings, plan `check`/`run`, consulta de sesiones y parada de sesión. Las acciones `check`, `run` y detener requieren confirmación; `LHOST` permanece limitado a loopback por el backend.

## `scope.yaml` y autorización

La CLI valida la referencia escrita desde `scope.yaml`. Para crear la configuración a partir del ejemplo:

```bash
cp scope.example.yaml scope.yaml
```

Completa `authorization_reference` con la ubicación del documento que cubre el alcance. Sin una referencia usable, el plan/dry-run puede servir como medición, pero la ejecución real se rechaza. No compartas el documento ni sus datos por la interfaz.

## API interno y diagnóstico

La GUI normalmente administra el proceso. Para diagnóstico manual (solo si no hay ya un proceso ocupando el puerto):

```bash
python3 web-ui/server.py
curl http://127.0.0.1:8765/api/status
```

Solo se conservan endpoints `/api/*`; el listener está fijado a `127.0.0.1`. No se debe cambiar a `0.0.0.0` ni publicar el servicio.

## Validación sin escaneos

```bash
python3 -m py_compile pentestx_gui.py pentestx_gui_backend.py pentestx.py pentestx_controlled.py web-ui/server.py
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s web-ui -p 'test_server.py' -v
python3 -m unittest discover -s web-ui/engine -p 'test_engine.py' -v
python3 -m unittest discover -s web-ui/tools -p 'test_moodle_sqli.py' -v
```

Las pruebas de GUI usan backend falso y no necesitan display; la prueba visual requiere Tkinter y una sesión gráfica. Las validaciones no ejecutan una evaluación contra un target. Licencia MIT.
