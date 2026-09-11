# Tutorial de PentestX GUI

## 1. Propósito

`pentestx_gui.py` es una interfaz de escritorio local construida con **Tkinter/ttk**. Presenta visualmente el planificador de PentestX y delega la validación de target, alcance, autorización, perfiles, límites y generación de evidencia en `pentestx.py`. No abre un servidor web, no modifica `kk2_repaired.py` y no ejecuta nada en segundo plano después de cerrar la ventana.

La interfaz está pensada para operadores que necesitan revisar un plan antes de iniciar una evaluación autorizada. El diseño usa una jerarquía de cuatro bloques: **alcance**, **fases**, **parámetros** y **consola de ejecución**.

## 2. Instalación y arranque

En Kali o en una distribución con Python 3 y Tkinter:

```bash
sudo apt update
sudo apt install -y python3 python3-tk
cd /ruta/al/repositorio
python3 pentestx_gui.py
```

La GUI no requiere paquetes Python adicionales para funcionar. `PyYAML` continúa siendo opcional y solo se necesita para cargar políticas YAML.

## 3. Ejecutar un plan autorizado

1. Escribe un **Target** que controles o que esté incluido en una autorización escrita.
2. Selecciona `passive` para comenzar sin tráfico activo o `active` si el alcance aprobado lo permite.
3. Marca las fases necesarias. Si no se marca ninguna, la interfaz usa `passive` como valor seguro.
4. Revisa la tabla **PLAN OVERVIEW**, el workspace y los parámetros.
5. Marca **Autorización escrita** y pulsa **Ejecutar**.
6. Acepta la confirmación visual solo después de revisar el alcance.
7. Revisa el workspace indicado y conserva únicamente la evidencia que corresponda a las reglas de compromiso.

La GUI no incluye una acción dry-run. Para generar un manifiesto sin tráfico, usa la opción `--dry-run` de la CLI.

## 4. Configuración de fases

Las fases disponibles son las acciones soportadas por la CLI: reconocimiento pasivo/activo, enumeración web, puertos, vulnerabilidades, revisión OWASP, revisión de findings, correlación, reporte, escaneo intrusivo controlado, perfiles allowlisted y pipelines correlacionados. Los parámetros de pipeline, perfil OWASP, perfil de herramienta, findings y exclusiones se pasan a la capa CLI sin reimplementar su lógica.

Para un pipeline correlacionado, selecciona `correlated` y elige `standard`, `with_intrusive`, `with_owasp` o `full_web`. Para `intrusive`, deja `auto` salvo que el propietario del alcance haya aprobado un perfil explícito. Los campos de puertos, tasa y timeout respetan las validaciones y los topes de `pentestx.py`.

## 5. Evidencia y resultados

La consola muestra stdout y stderr combinados del proceso. Los artefactos se escriben bajo el workspace configurado, incluyendo manifiestos de sesión, findings, capturas hashadas y reportes cuando la fase correspondiente se ejecuta. El código de salida aparece en la etiqueta de estado superior.

Los findings generados por la revisión basada en evidencia siguen requiriendo revisión manual.

## 6. Comprobación local sin tocar la red

```bash
python3 -m py_compile pentestx_gui.py pentestx.py kk2_repaired.py
printf 'q\n' | python3 pentestx.py --interactive --no-animate --no-color
python3 pentestx.py --target example.com --scope passive \
  --action passive correlate report \
  --confirm-written-authorization --dry-run
```

Para verificar la interfaz en una sesión gráfica, arráncala y usa un target de documentación como `example.com`; la interfaz no resuelve el target localmente.

## 7. Resolución de problemas

Si Python informa que no existe `tkinter`, instala el paquete del sistema `python3-tk`. Si una fase rechaza la operación, lee el mensaje de la consola: la interfaz no omite las restricciones de la CLI. Si un perfil YAML no carga, valida primero su sintaxis con `yaml.safe_load` y confirma que las claves estén dentro de las allowlists documentadas.

Usa únicamente targets propios o expresamente autorizados. No introduzcas credenciales, cookies, secretos ni datos de producción en los campos de la GUI o en archivos de evidencia.


## 8. Propuesta visual inspirada en Ettercap

La segunda iteración adopta una composición de estación de trabajo similar a la de herramientas clásicas GTK de seguridad, tomando como referencia la organización visual de Ettercap: **menú superior**, **barra de acciones**, **árbol de operaciones**, **área central de sesión**, **inspector lateral** y **barra de estado**. La referencia es únicamente de composición y densidad; no se copiaron funciones, código, identidad visual ni operaciones de Ettercap.

La adaptación a PentestX cambia los conceptos de red por los propios de esta herramienta: `TARGET SCOPE`, fases autorizadas, `SESSION MAP`, `SESSION INSPECTOR`, findings, pipelines, perfiles allowlisted y consola de `pentestx.py`. No se añadieron sniffing, ARP poisoning, MITM, interceptación, filtrado de tráfico ni otras funciones de Ettercap.

El árbol izquierdo permite activar o desactivar fases; el panel central muestra el plan y la consola; el inspector derecho concentra pipeline, perfiles, findings, políticas YAML y workspace. La configuración mantiene el mismo contrato de seguridad de la CLI.


## 9. Detección de parámetros y sugerencias

La GUI clasifica el target **solo por sintaxis local**, sin resolver DNS, hacer ping ni generar solicitudes. Reconoce IP, dominio, URL HTTP/HTTPS, red CIDR, lista de targets y valores inválidos.

Al escribir un target muestra una recomendación conservadora basada en el tipo detectado. Por ejemplo, una URL sugiere comenzar con `passive` y el pipeline `with_owasp`; una IP sugiere `host_baseline` únicamente si existe autorización para una fase activa; y una red CIDR sugiere `standard` antes de considerar `network_bounded`.

Las sugerencias no se aplican de manera automática. El operador debe pulsar **Aplicar sugerencia**, revisar los valores modificados y volver a revisar target, scope, fases y autorización antes de previsualizar o ejecutar. El botón no ejecuta procesos ni tráfico.


## 10. Reglas basadas en puertos detectados

El inspector incluye `Detected ports` y los botones **Analizar puertos** y **Aplicar regla**. El operador puede introducir una lista de puertos o cargar un `findings_db.json` local. La GUI solo lee campos semánticos como `port`, `ports`, `open_ports` o `detected_ports`; no ejecuta Nmap, no consulta servicios y no resuelve hosts.

Las reglas actuales son conservadoras:

| Puertos | Sugerencia |
|---|---|
| HTTP/HTTPS y alternativos (`80`, `443`, `8000`, `8080`, `8443`, etc.) | `with_owasp` y revisión de headers/métodos; propone los puertos web detectados para una fase posterior. |
| Bases de datos (`1433`, `1521`, `3306`, `5432`, `6379`, `9200`, `27017`) | `standard` y revisión pasiva; nunca propone credenciales o extracción. |
| SMB/NFS (`139`, `445`, `2049`) | `standard` y revisión pasiva; requiere revisar el alcance antes de enumerar. |
| SSH/Telnet/RDP (`22`, `23`, `3389`) | `standard` y revisión pasiva; no habilita fuerza bruta ni autenticación automática. |
| DNS (`53`) | `standard`; la GUI no realiza consultas DNS. |
| Otros | `standard` y revisión manual. |

Las reglas no se aplican automáticamente. **Aplicar regla** solo modifica el pipeline y, para puertos web, el campo de puertos intrusivos. El plan debe revisarse y continuar en `dry-run` antes de cualquier ejecución.


### Reglas adicionales de servicios comunes

| Servicio y puertos | Recomendación segura |
|---|---|
| SSH (`22`) | Revisión pasiva de versión, configuración y exposición. |
| FTP/FTPS (`21`, `990`) | Revisión pasiva de cifrado, modo anónimo y configuración. |
| SMTP (`25`, `465`, `587`) | Revisión pasiva de TLS, banner y relay autorizado. |
| POP3/IMAP (`110`, `143`, `993`, `995`) | Revisión pasiva de TLS y configuración; no se accede a buzones. |

Estas reglas no prueban credenciales, no envían mensajes, no abren sesiones contra los servicios y no activan fuerza bruta. Solo generan una recomendación de plan `standard` que el operador debe revisar.


### Reglas específicas de bases de datos

| Motor | Puerto | Recomendación segura |
|---|---:|---|
| MySQL | `3306` | Revisar pasivamente exposición, TLS y configuración. |
| PostgreSQL | `5432` | Revisar pasivamente exposición, TLS y configuración. |
| Redis | `6379` | Revisar pasivamente exposición y controles de acceso. |

Estas reglas tienen prioridad sobre la regla genérica de bases de datos. Solo generan una sugerencia `standard`; no prueban credenciales, no consultan tablas o claves y no envían comandos a los servicios.


## 11. Pestaña de telemetría integrada

La GUI incorpora el emisor del repositorio `kali-telemetry-gui` como una pestaña independiente: **◉ Telemetría**. La pestaña **◈ PentestX** conserva el planificador de evaluaciones y no comparte controles visuales con el panel de telemetría.

El panel integrado permite configurar URL HTTP `GET`/`POST`, destino UDP, puerto, BSSID contextual, intentos totales y backoff. También permite guardar la configuración, encolar un mensaje de prueba, cargar un TXT local de hasta 1 MiB y consultar las métricas de cola, envíos, fallos y reintentos.

El módulo integrado es `telemetry_sender.py` y conserva el envío asíncrono, los límites de 1–1000 intentos y el tratamiento del TXT como datos. El cierre de la ventana detiene el worker del emisor. La telemetría permanece separada de las operaciones PentestX: cambiar de pestaña no ejecuta un plan ni inicia tráfico por sí solo.

Usa exclusivamente receptores que controles o para los que tengas autorización. UDP no cifra ni confirma procesamiento de aplicación; para HTTP prefiere HTTPS cuando corresponda.
