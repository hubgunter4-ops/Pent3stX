# Validación de Pent3stX Workbench

Fecha de validación de esta migración: 2026-11-28.

## Cobertura de escritorio y backend

| Prueba | Resultado |
|---|---|
| `py_compile` de `pentestx_gui.py`, `pentestx_gui_backend.py`, `web-ui/server.py` y módulos CLI | Correcta; no requiere crear una ventana. |
| Importar la GUI en Python sin Tkinter | Correcta; la aplicación informa el requisito de sistema al arrancar. |
| Instanciación Tkinter visual en este sandbox | Omitida: Tkinter no está instalado en este Python. No se instaló ningún paquete. |
| Cliente loopback, URL fija, rutas `/api/*`, JSON y errores HTTP | Correcta con mocks. |
| Identidad del backend local | Correcta: acepta solo raíz coincidente; rechaza servicio no verificado sin enviar acciones. |
| Ciclo de vida de proceso | Correcta con mocks: crea lista de argumentos `shell=False` y termina solo el proceso que inició. |
| Preview principal | Correcta con backend falso: envía `/api/plan`, muestra comando exacto y no ejecuta. |
| Dry-run obsoleto | Correcta: cambia el fingerprint con target/scope/pipeline/fase y no habilita ejecución. |
| Confirmación de ejecución | Correcta con fake backend: `/api/execute` solo se prepara tras pasar por el callback de confirmación y envía ambos booleanos `true`. |
| Preferencias | Correcta: serializa solo target/scope/pipeline; cookie, sesskey y token no se incluyen. |
| API-only | Correcta: `GET /` y una ruta estática desconocida devuelven `404` JSON; `/api/status` permanece disponible. |
| Referencia scope sin PyYAML | Correcta: fallback de sintaxis limitada acepta el ejemplo documentado y rechaza YAML malformado, placeholders, null, booleanos y números. |

## Comandos

```bash
python3 -m py_compile pentestx_gui.py pentestx_gui_backend.py pentestx.py pentestx_controlled.py telemetry_sender.py web-ui/server.py web-ui/engine/engine.py web-ui/tools/moodle_sqli.py web-ui/msf/msf_client.py
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s web-ui -p 'test_server.py' -v
python3 -m unittest discover -s web-ui/engine -p 'test_engine.py' -v
python3 -m unittest discover -s web-ui/tools -p 'test_moodle_sqli.py' -v
```

Las suites existentes también cubren guardrails y ejecuciones dry-run con mocks. No se hizo tráfico de evaluación contra targets, no se inició una evaluación real, no se leyó ni alteró `scope.yaml`, y no se instalaron dependencias.

## Revisión visual pendiente por dependencia del entorno

`Xvfb` está disponible, pero el intérprete no incluye el módulo Tkinter; por eso no se pudo lanzar la ventana ni generar una captura funcional final. La propuesta aprobada sigue en `previews/proposed.png`; para una revisión visual real, instala `python3-tk` en el sistema de ejecución con autorización del operador y lanza `python3 pentestx_gui.py` bajo una sesión gráfica.
