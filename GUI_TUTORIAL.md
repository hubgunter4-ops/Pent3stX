# Tutorial de Pent3stX Workbench (Tkinter/ttk)

## 1. Propósito y arquitectura

`pentestx_gui.py` es una aplicación de escritorio local. Presenta el Workbench de Pent3stX y delega validación, guardrails, planificación, ejecución y evidencia en el backend existente (`web-ui/server.py`), que ahora es una API interna en `127.0.0.1:8765` y no sirve páginas web. El backend se inicia/verifica como proceso local y se cierra solo si lo inició esta GUI.

La GUI no importa ni restaura módulos del legado `archive/kk2_legacy.py`. Usa Tkinter/ttk y bibliotecas estándar; no requiere instalar paquetes pip.

## 2. Requisitos y arranque

Se necesita Python 3 y el módulo Tkinter de la misma instalación. En Debian/Kali, si el import de tkinter no está disponible, el paquete del sistema suele llamarse `python3-tk`.

```bash
cd /ruta/al/repositorio
python3 pentestx_gui.py
```

No hace falta iniciar el backend manualmente. Si el puerto local `8765` ya tiene un servicio, la GUI verifica `/api/status` y solo se conecta si la raíz y la identidad corresponden a este repositorio. Un servicio no verificado provoca un error y no recibe acciones.

## 3. Configuración y target editable

En la barra superior del Workbench:

- **Target** es texto libre editable; no hay autocompletado ni sugerencias.
- **Scope** es `passive` o `active`.
- **Pipeline** es `standard`, `with_intrusive`, `with_owasp` o `full_web`.
- **Aplicar** solo confirma localmente los valores visibles; la validación autoritativa ocurre en el servidor.
- **Guardar** persiste target, scope y pipeline en `$XDG_CONFIG_HOME/pentestx/preferences.json` o `~/.config/pentestx/preferences.json`. Nunca se guardan cookies, sesskey ni el token de Metasploit.

El backend aplica su allowlist exacta y valida sin resolver DNS. Las acciones activas y los pipelines intrusivos requieren `scope=active`.

## 4. Plan y ejecución

1. Selecciona una fase en `OPERATIONS • PHASES`.
2. Pulsa **Ver plan (dry-run)**. El backend devuelve el comando y manifiesto exactos; la GUI los muestra, pero no ejecuta el assessment.
3. Solo si el dry-run fue aprobado para la configuración actual se habilita **Ejecutar**.
4. Revisa la confirmación modal y marca **“Confirmo que tengo autorización escrita para este alcance”**. El backend requiere además una referencia usable en `scope.yaml`; la casilla no sustituye el documento.
5. Usa **Pausar / detener** para pedir `/api/stop` durante una evaluación iniciada desde esta GUI. Al cerrar, si la GUI inició el backend y hay una evaluación activa, solicita la parada antes de cerrar. Si el backend preexistía y se verificó, no detiene un servicio compartido.

Cualquier cambio a target, scope, pipeline o fase invalida el preview; hay que volver a generar el dry-run. No se ejecutan escaneos durante pruebas de la GUI.

## 5. Sesiones, findings y archivos

`Session Map` muestra sesiones reales que el backend encontró en el workspace, `Plan Overview` conserva el último comando dry-run, `Tasks` indica el estado y el Inspector permite revisar pipeline, perfiles allowlisted y findings. **Actualizar sesiones** y **Cargar findings** consultan evidencia local ya generada.

**Abrir** e **Importar** leen un archivo local de hasta 1 MiB como datos informativos; no lo ejecutan ni aplican contenido a la configuración. **Exportar** escribe un informe JSON con la sesión seleccionada y findings; la selección de ruta la realiza el usuario.

## 6. Motor y adaptadores

### Motor de planificación

En **Evaluaciones → Motor: generar plan…**, selecciona uno de los goals del backend (`owasp_report`, `full_assessment`, `moodle_sqli_confirm` o `msf_targeted`). El plan aparece redactado y no ejecuta hasta que se confirma mediante la casilla. Para `moodle_sqli_confirm`, sesskey y cookie son campos enmascarados en memoria; un cambio en target/scope/goal/credenciales invalida el plan.

### Moodle SQLi (local)

En **Herramientas → Moodle SQLi (local)…**, el destino permanece fijado en `http://127.0.0.1:8080/moodle`. Introduce sesskey y cookie vigentes; selecciona solo `database`, `username` o ambos. Usa primero **Dry-run payloads**; después revisa la salida y confirma la ejecución con la casilla. No se extrae password hash.

### Metasploit local

En **Herramientas → Metasploit (local)…** puedes comprobar estado, buscar módulos, consultar detalles, editar las opciones JSON, generar un plan `check` o `run`, correlacionar findings existentes y ver/parar sesiones. El token se oculta y solo vive en memoria. La búsqueda y correlación son consultas de lectura; `check`, `run` y detener sesión muestran una confirmación explícita. Las reglas finales de target, `LHOST` y acciones peligrosas las aplica el backend/`msfmcpd`.

## 7. Solución de problemas y pruebas

- **No existe `tkinter`:** instala el paquete del sistema que proporciona Tkinter para tu versión de Python; no se soluciona con `pip install tkinter`.
- **Backend no verificado o puerto ocupado:** confirma que no haya otro servicio en `127.0.0.1:8765`; la GUI no se conecta a un proceso cuya identidad no coincida.
- **Dry-run rechazado:** revisa el mensaje del backend, el target, scope, pipeline y referencia `scope.yaml`.
- **Ejecución rechazada:** verifica autorización escrita, la casilla y la referencia usable en `scope.yaml`.

Pruebas unitarias seguras (mocks/dry-run, sin evaluar un objetivo):

```bash
python3 -m py_compile pentestx_gui.py pentestx_gui_backend.py web-ui/server.py
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s web-ui -p 'test_server.py' -v
```
