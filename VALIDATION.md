# Validación de PentestX autorizado

Fecha de validación: 2026-08-26.

| Prueba | Resultado |
|---|---|
| `python3 -m py_compile kk2_repaired.py pentestx.py` | Correcta. |
| `python3 pentestx.py --help` | Correcta. |
| `python3 pentestx.py --check-tools` | Correcta; reporta dependencias disponibles sin invocar red. |
| Simulación con `--dry-run` | Correcta; genera manifiesto y no ejecuta funciones ni tráfico. |
| Acción activa sin confirmación | Rechazada con código de salida 2. |
| Menú interactivo con `q` | Sale sin ejecutar acciones. |
| Menú interactivo: añadir pasivo y seleccionar activo en modo pasivo | Añade el reconocimiento pasivo y rechaza la acción activa hasta habilitar el alcance. |
| Fase `vulnerability` con `findings_db.json` local | Convierte indicadores `vulns` y `nuclei` en 2 candidatos y genera JSON/Markdown sin tráfico. |
| Menú interactivo con fase `vulnerability` | Permite seleccionar fuente, añadir `[0]` y ejecutar sin target cuando solo se analiza evidencia local. |
| Perfiles YAML | Carga `profiles.example.yaml` con `yaml.safe_load` y lista perfiles fijos y personalizados. |
| Instalación en `dry-run` | Muestra únicamente paquetes `ffuf`/`sqlmap` y no ejecuta `apt-get`. |
| Selección automática de findings | Un perfil `sqlmap` reutiliza el target de un hallazgo `sqli` cuando no se proporciona `--target`. |
| Política con clave `command` no permitida | Rechazada con código de salida 2 antes de cualquier ejecución. |
| Menú interactivo actualizado | Expone perfiles, instalación, fuente de findings y ejecución de perfil; salir con `q` no ejecuta acciones. |
| Instalación simulada en Ubuntu, Kali y Fedora | Genera comandos `apt-get` para Ubuntu/Kali y `dnf` para Fedora sin ejecutar cambios. |
| Instalación individual de nmap | Instala únicamente el paquete allowlisted solicitado en `dry-run`. |
| Instalador unificado de dependencias | `--install-dependencies` planifica Python, Tkinter, PyYAML, coreutils y ffuf/sqlmap/nmap/traceroute para Ubuntu, Kali y Fedora. |
| Instalador sin confirmación | Rechaza la ejecución real antes de invocar `apt-get` o `dnf`. |
| Pruebas unitarias del instalador | `python3 -m unittest discover -s tests -v` ejecuta 4 pruebas correctamente. |
| Escaneo intrusivo en `dry-run` | Construye comando Nmap limitado por puertos, tasa, timeout y exclusiones sin tráfico. |
| Target cubierto por exclusión CIDR | Rechazado con código de salida 2 antes de iniciar el escaneo. |
| Auto-perfil para IP | Selecciona `host_baseline` con puertos de host y límites conservadores. |
| Auto-perfil para dominio | Selecciona `domain_web` con puertos HTTP alternativos. |
| Auto-perfil para URL HTTP/HTTPS | Selecciona `url_web` y usa solo el hostname para Nmap. |
| Auto-perfil para CIDR | Selecciona `network_bounded` y conserva el límite de 256 direcciones. |
| Captura persistente | Genera `intrusive_scan_manifest.json` y `capture_manifest.json` con tamaño y SHA-256. |
| Menú de auto-perfil | Permite elegir `auto` o perfil explícito y mantiene `dry-run` hasta ejecutar el plan. |
| Listado de auto-perfiles | `--list-intrusive-profiles` muestra perfiles, tipos, puertos, tasa y timeout sin tráfico. |
| Clasificación automática de IP | Selecciona `host_baseline` y usa puertos `22,80,443,8080,8443`. |
| Clasificación automática de dominio | Selecciona `domain_web` y usa puertos web alternativos. |
| Clasificación automática de URL | Selecciona `url_web` y normaliza a hostname para Nmap. |
| Clasificación automática de CIDR | Selecciona `network_bounded` y mantiene límite de 256 direcciones. |
| Menú guiado con auto-perfil | Selecciona `auto`, añade `[x]` y genera captura persistente en `dry-run`. |
| Pipeline correlacionado estándar | `--action correlated --pipeline-profile standard` enumera las fases en orden y genera manifiesto sin tráfico en `dry-run`. |
| Pipeline correlacionado con intrusivo | `with_intrusive` añade el auto-perfil intrusivo y conserva su captura en `dry-run`. |
| Menú `[k]` de pipeline | Permite seleccionar `standard` o `with_intrusive` y añadirlo al plan. |
| `traceroute` ausente en `active` | Se convierte en advertencia opcional tanto en `active` directo como en el pipeline; no propaga `FileNotFoundError`. |
| Persistencia del pipeline | Genera `correlated_pipeline/pipeline_manifest.json` y su `capture_manifest.json`. |
| Conservación de clases y funciones del módulo legado | Verificada por la capa auxiliar; no se reescribieron definiciones. |
| Panel Tactical Neon sin TTY | Muestra paneles alineados y sale con `q` sin códigos ANSI. |
| `--no-animate --no-color` | Mantiene la estructura del panel, elimina efectos y no emite escapes ANSI. |
| Panel bajo pseudo-TTY | Muestra banner, colores ANSI, transiciones y menú estructurado. |
| Menú persistente tras varias respuestas | `OPERATIONS // SELECT ACTION` aparece una sola vez; el estado se refresca sin redibujar el menú. Verificado con varias respuestas. |
| Menú persistente con cambio de target | La selección se refleja en `SESSION STATUS // LIVE` mediante actualización del dashboard. |
| Menú persistente con `--no-animate --no-color` | Mantiene layout y salida incremental sin códigos ANSI ni saltos literales. |
| Menú paginado en modo plano | Navega `LAYER 1/3`, `LAYER 2/3` y `LAYER 3/3` con `n`/`b` sin perder opciones. |
| Menú paginado bajo pseudo-TTY | La transición reemplaza el bloque de operaciones en sitio y no acumula páginas. |
| Banner animado compacto | Los frames se reescriben en el mismo bloque y no crean cajas verticales adicionales. |
| Limpieza inicial TTY | Emite una sola limpieza de pantalla al entrar en el menú y ancla el dashboard desde una posición fija posterior al banner. |
| Coordenadas estables | El panel se refresca desde sus filas calculadas y no sobrescribe líneas previas del shell. |
| Buffer alternativo TUI | Bajo pseudo-TTY activa una pantalla aislada (`?1049h`) y la restaura al salir (`?1049l`). |
| Entrada sin duplicación | Las respuestas de `pentestx>` no generan un segundo `SESSION STATUS` ni hacen desaparecer la capa activa. |
| Módulo `owasp_web` en `dry-run` | Carga perfil, clasifica target y genera plan sin solicitudes de red. |
| Perfil OWASP fijo | `owasp_web_intrusive` valida checks A01–A10 con GET, límites y sin redirecciones. |
| Diez perfiles OWASP YAML | `owasp_profiles.example.yaml` carga un perfil A01–A10 por categoría con `yaml.safe_load`. |
| Claves OWASP no permitidas | Rechaza payloads, command, auth, post_data, métodos mutantes y redirecciones. |
| Findings OWASP | Genera `owasp_findings.json`, `OWASP_WEB_REPORT.md` y captura hashada local. |
| Pipeline `with_owasp` | Integra `owasp_web` entre enumeración y correlación en `dry-run`. |
| Pipeline `full_web` | Integra OWASP junto con puertos, vulnerabilidades e intrusivo controlado. |
| Menú OWASP | Expone acción `[w]` y selector `[y]` sin redibujar el menú persistente. |
| Barra de progreso de ejecución | Se integra en el runner externo sin alterar las llamadas del legado. |

La copia ejecutable `kk2_repaired.py` completa la cola truncada de `menu_scan()` sin cambiar las firmas ni la lógica previa de sus funciones. La capa externa maneja `traceroute` mediante un adaptador opcional cuando se ejecuta `active` o un pipeline correlacionado.

La herramienta no expone desde su CLI ni desde el menú guiado las funciones originales de fuerza bruta, explotación, post-explotación, persistencia, pivoting, exfiltración o wireless. Las funciones siguen presentes en el módulo legado porque se solicitó conservarlas, pero la capa externa ofrece acciones de reconocimiento, enumeración web, escaneo, correlación, reporting, revisión basada en evidencia, perfiles limitados para `ffuf`/`sqlmap` y un escaneo intrusivo controlado de Nmap. La fase `vulnerability` solo procesa resultados ya registrados; los perfiles requieren findings compatibles, no habilitan extracción de datos, shells ni cambios de estado, y sus argumentos se construyen mediante allowlist. La persistencia implementada es únicamente local para evidencias y manifiestos; no establece persistencia en el target. Todas las acciones sobre targets requieren que el operador declare autorización escrita; las acciones activas requieren además `--scope active`.

### Validación de la interfaz gráfica

| Prueba | Resultado |
|---|---|
| `python3 -m py_compile pentestx_gui.py pentestx.py kk2_repaired.py` | Correcta. |
| GUI sin acción dry-run | Implementada; la ejecución requiere autorización y confirmación visual. |
| `pentestx.py` dry-run desde el flujo documentado | Correcta; salida 0 y manifiesto local. |
| Comprobación de herramientas desde la GUI | Aislada como operación de mantenimiento sin target ni fases seleccionadas. |
| Confirmación de ejecución real | Requiere autorización marcada y confirmación visual. |
| Documentación | `GUI_TUTORIAL.md` y sección dedicada en `README.md`. |
