# PentestX autorizado

Este paquete contiene una reparación mínima de `kk2.py` y una herramienta auxiliar de ejecución. El archivo `kk2_original.py` es una copia exacta del adjunto recibido. El archivo `kk2_repaired.py` conserva la misma clase y las mismas funciones originales; únicamente se completó el fragmento truncado al final de `menu_scan()` para que el módulo pueda compilarse.

La herramienta `pentestx.py` funciona como una capa externa. No reescribe ni duplica la lógica del módulo legado: valida los argumentos, exige que se declare autorización escrita, prepara un workspace por sesión, invoca las funciones existentes en un orden explícito, registra un manifiesto JSON y deja los logs producidos por el módulo original. El uso debe limitarse a activos propios o cubiertos por autorización escrita y por unas reglas de compromiso vigentes.

## Archivos

| Archivo | Propósito |
|---|---|
| `kk2_original.py` | Copia intacta del script entregado. |
| `kk2_repaired.py` | Copia reparada solo en el punto de truncamiento sintáctico. |
| `pentestx.py` | CLI externa para validar alcance, ejecutar funciones y mostrar el panel Tactical Neon. |
| `profiles.example.yaml` | Plantilla de política YAML para perfiles ffuf/sqlmap personalizados. |
| `owasp_profiles.example.yaml` | Diez perfiles OWASP Top 10:2025 con checks web read-only. |
| `OWASP_WEB_FINDINGS_PIPELINES.md` | Findings, pipelines y ejemplos YAML del módulo web OWASP. |
| `requirements.txt` | Dependencia opcional para cargar políticas YAML. |
| `workspace/` | Directorio generado para sesiones, logs, JSON y reportes. |

## Comprobación rápida

```bash
cd /home/ubuntu/pentestx_autorizado
python3 -m py_compile kk2_repaired.py pentestx.py
python3 pentestx.py --help
python3 pentestx.py --check-tools
```

La comprobación de dependencias no necesita target. Las herramientas ausentes se reportan como una limitación de cobertura; no deben interpretarse como ausencia de vulnerabilidades.

## Menú interactivo de ejecución guiada

Para abrir el menú interactivo usa:

```bash
python3 pentestx.py --interactive
```

El menú permite configurar el target, seleccionar el alcance pasivo o activo, comprobar dependencias, listar perfiles, instalar paquetes allowlisted, seleccionar un `findings_db.json`, añadir acciones al plan, revisar el plan y ejecutarlo explícitamente. La opción `r` no ejecuta nada si falta target cuando la acción lo necesita, si no hay acciones seleccionadas o si no se confirma la autorización escrita. Las acciones activas no pueden añadirse mientras el alcance sea `passive`; al habilitar `active`, el menú solicita una confirmación independiente.

El flujo guiado ofrece reconocimiento pasivo, reconocimiento activo, enumeración web, escaneo de puertos, escaneo de vulnerabilidades, escaneo web OWASP Top 10:2025, escaneo intrusivo controlado, correlación, reporte, una fase externa de vulnerabilidades basada en resultados, ejecución de perfiles controlados y un pipeline correlacionado. Las acciones `ports` y `vuln` conservan los menús interactivos internos del módulo original. Para salir sin ejecutar se usa `q`.

El módulo OWASP se configura con `--owasp-profile` y `--owasp-policy-file`; el documento `OWASP_WEB_FINDINGS_PIPELINES.md` contiene el modelo de findings, los pipelines `with_owasp`/`full_web` y diez perfiles YAML, uno por categoría OWASP Top 10:2025.

### Panel Tactical Neon

El menú interactivo utiliza un panel de estado alineado, banner de arranque, colores ANSI, transiciones de pantalla, spinner, barra de progreso y mensajes de estado `[✓]`, `[!]` y `[x]`. Las animaciones se activan automáticamente solo cuando la salida es un TTY. En SSH interactivo se mantienen; en pipes, CI y redirecciones se desactivan automáticamente para no contaminar logs.

El layout del menú es persistente y paginado. Cada capa muestra una parte de las opciones originales con números y letras; `[n]` avanza y `[b]` retrocede. Al entrar en modo interactivo bajo TTY se activa un buffer alternativo, se oculta temporalmente el cursor y se limpia la superficie una vez; al salir, la terminal se restaura. Así, el prompt del shell o líneas previas no pueden crear un panel duplicado. Cada actualización redibuja solo el dashboard dentro de esa superficie aislada. En terminales sin TTY se usa el fallback incremental sin códigos de control.

Para forzar compatibilidad plana usa:

```bash
python3 pentestx.py --interactive --no-animate --no-color
```

También puedes desactivar la animación mediante `PENTESTX_NO_ANIMATE=1`. La opción `--no-color` elimina los códigos ANSI y `--no-animate` conserva el panel pero elimina limpieza de pantalla, spinners, transiciones y barras animadas.

## Perfiles fijos y política YAML

El wrapper incluye los perfiles fijos `ffuf_safe` y `sqlmap_safe`. No aceptan comandos arbitrarios y mantienen límites de tasa, concurrencia, timeout, reintentos y solicitudes. Solo pueden instalar los paquetes `ffuf` y `sqlmap` desde el gestor de paquetes del sistema. El perfil `ffuf_safe` requiere una wordlist absoluta y el perfil `sqlmap_safe` requiere una URL con parámetro y conserva `level=1`, `risk=1`, una única hebra y técnica `BE`.

Lista los perfiles con:

```bash
python3 pentestx.py --list-profiles
```

Instala de forma explícita y separada de la ejecución:

```bash
python3 pentestx.py \\
  --profile ffuf_safe \\
  --install-tools \\
  --confirm-tool-install
```

Para perfiles personalizados, usa `profiles.example.yaml` como plantilla y carga la política con `--policy-file`:

```bash
python3 pentestx.py \\
  --policy-file profiles.example.yaml \\
  --list-profiles
```

La política se carga con `yaml.safe_load`, no puede sobrescribir perfiles fijos, no puede cambiar el binario o paquete fuera de la allowlist y rechaza claves desconocidas, rutas relativas, valores fuera de rango y herramientas no permitidas. Instala PyYAML con `python3 -m pip install -r requirements.txt` cuando uses políticas YAML.

La instalación es explícita y separada de la ejecución. Con `--distro auto` se lee `/etc/os-release`; Ubuntu y Kali usan `apt-get`, mientras Fedora usa `dnf`. Puedes seleccionar perfiles o herramientas individuales con `--install-tools` y `--install-tool`. El instalador solo permite `ffuf`, `sqlmap`, `nmap` y `traceroute`, y genera `installation_manifest.json`. Usa `--dry-run` para revisar los comandos sin instalar nada.

Ejemplos:

```bash
python3 pentestx.py --distro ubuntu --install-tool nmap --confirm-tool-install
python3 pentestx.py --distro kali --profile ffuf_safe --install-tools --confirm-tool-install
python3 pentestx.py --distro fedora --profile sqlmap_safe --install-tools --confirm-tool-install
```

## Ejecución automática basada en findings

La acción `tool` selecciona automáticamente el hallazgo más reciente compatible con el perfil. Si no se proporciona `--findings-file`, busca el último `findings_db.json` bajo `workspace/pentestx_sessions/`. Para ffuf se aceptan categorías como `directories`, `nuclei`, `nikto_findings` o `nmap_output`; para sqlmap se exige `sqli`. Si el hallazgo contiene un target válido, puede reutilizarse cuando no se indica `--target`.

Ejemplo de previsualización sin ejecutar la herramienta:

```bash
python3 pentestx.py \\
  --scope active \\
  --action tool \\
  --profile sqlmap_safe \\
  --confirm-written-authorization \\
  --findings-file /ruta/a/findings_db.json \\
  --dry-run
```

En modo real, cada ejecución genera `tool_runs/<perfil>/tool_run_manifest.json`, stdout, stderr y las salidas locales de la herramienta. Los perfiles no habilitan extracción de datos, shells, ejecución de comandos ni cambios de estado.

## Pipeline correlacionado

La acción `correlated` encadena funciones del menú en una secuencia reproducible y guarda los estados en `correlated_pipeline/pipeline_manifest.json`. `standard` ejecuta reconocimiento pasivo, reconocimiento activo, escaneo de puertos, enumeración web, escaneo de vulnerabilidades, revisión de findings, correlación y reporte. `with_intrusive` añade el escaneo intrusivo automático después de la enumeración.

La fase `active` trata `traceroute` como dependencia opcional. Si el binario no está instalado, se registra una advertencia `skipped_missing_dependency` y el pipeline continúa con las demás fases; ya no se produce un `FileNotFoundError` que aborte la sesión. El pipeline conserva además un índice local de captura.

Ejemplo en `dry-run`:

```bash
python3 pentestx.py \\
  --target 192.0.2.10 \\
  --scope active \\
  --action correlated \\
  --pipeline-profile with_intrusive \\
  --intrusive-profile auto \\
  --confirm-written-authorization \\
  --dry-run
```

En el menú, `[k]` permite elegir `standard` o `with_intrusive` y añadirlo al plan. La ejecución real sigue requiriendo `--scope active`, autorización escrita, target válido y exclusiones aprobadas.

## Escaneo intrusivo controlado

La acción `intrusive` ejecuta un perfil acotado de Nmap para un único target autorizado. Usa detección de servicios ligera, puertos limitados, tasa máxima, timeout, un reintento, exclusiones y salida local. No habilita scripts NSE arbitrarios, explotación, fuerza bruta, evasión ni ejecución de comandos.

Con `--intrusive-profile auto`, el wrapper clasifica el target sin resolverlo y selecciona `host_baseline` para una IP, `domain_web` para un dominio, `url_web` para una URL HTTP/HTTPS y `network_bounded` para un CIDR. Los perfiles explícitos solo se aceptan si son compatibles con el tipo detectado. La persistencia se refiere exclusivamente a la evidencia local de la sesión; no se crea persistencia en el sistema evaluado.

Ejemplo de previsualización sin tráfico:

```bash
python3 pentestx.py \\
  --target 192.0.2.10 \\
  --scope active \\
  --action intrusive \\
  --intrusive-profile auto \\
  --intrusive-ports 22,80,443,8000-8010 \\
  --intrusive-rate 10 \\
  --intrusive-timeout 60 \\
  --exclude 192.0.2.0/24 \\
  --confirm-written-authorization \\
  --dry-run
```

El perfil limita la cobertura a 2048 puertos y a redes de hasta 256 direcciones. En el menú interactivo, `[a]` selecciona el auto-perfil o uno explícito; `[c]` configura puertos, tasa, timeout y exclusiones; `[o]` selecciona `auto`, Ubuntu, Kali o Fedora; y `[x]` añade el escaneo al plan. Los artefactos se guardan bajo `intrusive_scan/<perfil>/`, junto con `intrusive_scan_manifest.json` y `capture_manifest.json`, que registra tamaño y SHA-256 de la evidencia.

## Fase de vulnerabilidades basada en resultados

La acción `vulnerability` no lanza un exploit ni realiza tráfico. Lee el `findings_db.json` de la sesión actual o un archivo proporcionado con `--findings-file`, identifica indicadores como `sqli`, `xss`, `lfi`, `vulns`, `nuclei`, `nikto_findings` y `nmap_output`, y los transforma en candidatos trazables con severidad, evidencia, hallazgo origen y siguiente paso de validación no destructiva.

En modo no interactivo:

```bash
python3 pentestx.py \\
  --action vulnerability \\
  --findings-file /ruta/a/findings_db.json
```

En modo interactivo, selecciona `[f]` para indicar el archivo de hallazgos, `[0]` para añadir la fase y `[r]` para ejecutarla. Selecciona `[t]` para añadir un perfil de herramienta, `[p]` para listar perfiles e `[i]` para instalar únicamente el paquete asociado después de confirmar. Se generan `vulnerability_review.json` y `VULNERABILITY_REVIEW.md` en la sesión actual. La revisión resultante es un conjunto de candidatos; no constituye autorización para explotar, modificar estado, acceder a datos reales ni realizar acciones fuera de las reglas de compromiso.

## Simulación sin tráfico

```bash
python3 pentestx.py \
  --target example.com \
  --scope passive \
  --action passive correlate report \
  --confirm-written-authorization \
  --dry-run
```

`--dry-run` valida el target, revisa la superficie de funciones y escribe el manifiesto de la sesión sin invocar funciones ni realizar tráfico de red.

## Ejecución pasiva

```bash
python3 pentestx.py \
  --target example.com \
  --scope passive \
  --action passive correlate report \
  --confirm-written-authorization
```

## Ejecución activa autorizada

Las acciones activas requieren simultáneamente `--scope active` y `--confirm-written-authorization`. Conserva las tasas y exclusiones definidas en las reglas de compromiso; no uses redes o dominios de terceros fuera del alcance documentado.

```bash
python3 pentestx.py \
  --target 192.0.2.10 \
  --scope active \
  --action active web ports vuln correlate report \
  --confirm-written-authorization
```

Las funciones originales `port_scan()` y `vuln_scan()` conservan sus menús interactivos internos. Por tanto, la herramienta solicitará la opción correspondiente cuando llegue a esas acciones. La capa externa no habilita ejecución arbitraria de comandos, fuerza bruta, persistencia, pivoting, exfiltración ni explotación personalizada.

## Uso directo no interactivo

También se puede construir el plan desde la línea de comandos:

```bash
python3 pentestx.py \\
  --target example.com \\
  --scope passive \\
  --action passive correlate report \\
  --confirm-written-authorization
```

## Estructura de salida

Cada importación del módulo legado crea una sesión en `workspace/pentestx_sessions/<timestamp>/`. La capa externa añade `execution_manifest.json` con el target declarado, el alcance, las acciones, la confirmación de autorización y el estado de ejecución. Cuando se ejecuta la fase de vulnerabilidades también conserva `vulnerability_review.json` y `VULNERABILITY_REVIEW.md`. Las ejecuciones de perfiles crean `tool_runs/<perfil>/tool_run_manifest.json`, stdout, stderr y resultados locales. El escaneo intrusivo crea `intrusive_scan/<perfil>/intrusive_scan_manifest.json`, stdout, stderr, formatos de salida de Nmap y `capture_manifest.json` con hashes SHA-256. El pipeline correlacionado crea `correlated_pipeline/pipeline_manifest.json` y su índice de captura. Las instalaciones crean `installation_manifest.json`. También se conservan `findings_db.json`, `attack_chains.json`, los logs por módulo y el reporte que genere el módulo original.

## Notas de reparación

El archivo original terminaba en una sentencia incompleta: `elif opt ==`. Esa línea provocaba `SyntaxError` durante la compilación. La copia reparada completa únicamente las ramas faltantes del menú de escaneo y deja la gestión de entrada, el registro, la correlación y el reporting en las funciones originales. No se han cambiado sus firmas ni se han incorporado funciones nuevas al módulo legado.

> Esta herramienta es un ejecutor de pruebas de seguridad autorizadas. La confirmación de la CLI no sustituye la autorización escrita ni las reglas de compromiso del propietario del activo.


## Interfaz gráfica PentestX GUI

El repositorio incluye `pentestx_gui.py`, una interfaz de escritorio local basada en **Tkinter/ttk**. Es una capa de presentación sobre `pentestx.py`: no duplica la lógica de validación ni modifica el módulo legado. El diseño propone una evolución visual del panel Tactical Neon de terminal hacia una consola operativa de escritorio con cuatro zonas claras:

- **Alcance y autorización:** target, scope y declaración visible de autorización escrita.
- **Fases del plan:** selección de acciones soportadas por la CLI.
- **Parámetros y evidencia:** pipelines, perfiles, findings, políticas YAML y límites del escaneo controlado.
- **Consola de ejecución:** salida en tiempo real, código de salida y estado de sesión.

La propuesta usa una paleta oscura de alto contraste, acentos cyan/azul para navegación, verde para estados seguros y ámbar/rojo para advertencias. El modo `dry-run` está activado por defecto para que la primera operación sea una revisión del plan. La ejecución real requiere desactivar `dry-run`, declarar autorización y aceptar una confirmación adicional.

### Arranque

```bash
sudo apt install -y python3-tk
python3 pentestx_gui.py
```

Consulta [`GUI_TUTORIAL.md`](GUI_TUTORIAL.md) para el flujo completo, las validaciones y la comprobación local.

### Compatibilidad

La interfaz requiere Python 3 y Tkinter. No añade dependencias Python obligatorias. Los controles de seguridad siguen centralizados en `pentestx.py`: las acciones activas exigen `--scope active` y `--confirm-written-authorization`; el modo `dry-run` no ejecuta funciones de red.


### Propuesta visual inspirada en Ettercap

La GUI adopta una composición de estación de trabajo similar a las herramientas clásicas GTK de seguridad: menú, toolbar, árbol de operaciones, mapa de sesión, inspector lateral, pestañas de consola/findings y barra de estado. Se utiliza únicamente como referencia de organización visual. La interfaz sigue siendo PentestX y no incorpora sniffing, MITM, ARP poisoning, interceptación, filtrado de tráfico ni ninguna otra función de Ettercap. El detalle del diseño y su flujo están documentados en [`GUI_TUTORIAL.md`](GUI_TUTORIAL.md).

### Ejemplo visual

La composición propuesta puede verse en [`docs/screenshots/pentestx-gui-ettercap-model.png`](docs/screenshots/pentestx-gui-ettercap-model.png). La imagen usa un target sintético de laboratorio y `dry-run`; es una referencia visual, no una ejecución.


### Detección local y sugerencias

La GUI clasifica sintácticamente IP, dominio, URL, CIDR y listas de targets sin resolverlos ni contactar la red. Según el tipo detectado propone un scope conservador, pipeline y perfil intrusivo compatible. Las sugerencias son explícitas y revisables: no se aplican ni ejecutan automáticamente. Consulta la sección correspondiente de [`GUI_TUTORIAL.md`](GUI_TUTORIAL.md).


### Sugerencias basadas en puertos

El inspector permite analizar puertos introducidos manualmente o extraídos de campos semánticos de un `findings_db.json` local. Las reglas sugieren `with_owasp` para servicios web y mantienen `standard` para bases de datos, SMB/NFS, SSH/Telnet/RDP y DNS, sin habilitar credenciales, fuerza bruta, extracción ni consultas de red. Las reglas son explícitas y revisables; no ejecutan escaneos ni se aplican automáticamente. El detalle está en [`GUI_TUTORIAL.md`](GUI_TUTORIAL.md).


La detección por puertos también reconoce SSH, FTP/FTPS, SMTP y POP3/IMAP. Para estos servicios solo recomienda revisión pasiva de configuración, cifrado, banners o exposición; no habilita autenticación, fuerza bruta, envío de mensajes ni acceso a buzones.
