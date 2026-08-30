# Laboratorio de demostración: extracción, bypass y canarios seguros

## Objetivo

Este material permite demostrar a un usuario el flujo de un hallazgo de seguridad sin tocar sistemas reales. Los escenarios apuntan exclusivamente a `127.0.0.1` o `localhost` en el puerto `8080`, usan datos sintéticos y esperan respuestas controladas. La palabra **extracción** representa la recuperación de un registro ficticio; **bypass** representa una comprobación negativa de control de acceso; y **payload** representa un canario literal que debe permanecer como texto.

> Ningún escenario de este documento debe ejecutarse contra un dominio público, una IP de producción o una cuenta real. Para una demostración, levanta una fixture local que implemente las rutas `/demo/extraction`, `/demo/access-check`, `/demo/input`, `/demo/reflect`, `/demo/directory-search`, `/demo/utility`, `/demo/profile` y `/demo/regression`.

## Escenarios incluidos

| Escenario | Qué demuestra | Resultado seguro |
|---|---|---|
| `extraction_simulation` | Recuperación de un registro sintético. | HTTP 200 con `DEMO_SYNTHETIC_RECORD_001`; ningún secreto real. |
| `access_bypass_simulation` | Rechazo de acceso de un actor `viewer`. | HTTP 403; sin datos privilegiados ni cambios de estado. |
| `sql_canary` | Tratamiento literal de una cadena SQL. | El canario vuelve como texto; no se ejecuta consulta. |
| `xss_canary` | Escape de una cadena reflejada. | El canario aparece como texto; no se ejecuta markup. |
| `ldap_canary` | Tratamiento literal de una búsqueda de directorio. | No se amplía el filtro ni se divulgan registros. |
| `command_canary` | Tratamiento literal de entrada para una utilidad. | No se invoca shell, proceso, archivo ni callback. |
| `modified_parameter_negative` | Validación de una variación de parámetros. | HTTP 403; sin cambio de privilegio o estado. |
| `extraction_redaction` | Captura de evidencia con redacción. | Solo se conserva salida sintética y `REDACTED`. |
| `bypass_replay_negative` | Repetición de una petición de actor sin privilegios. | Sigue en HTTP 403. |
| `combined_safe_regression` | Regresión conjunta de todos los canarios. | Todos vuelven como texto y ninguna operación tiene efecto. |

## Política YAML

La política está en `lab_demo_extraction_bypass_payloads.yaml`. Sus controles globales exigen loopback, permiten solo `GET`/`HEAD`, deshabilitan redirecciones, limitan tasa, concurrencia y timeout, y prohíben métodos mutantes. Los canarios no son payloads ejecutables: son identificadores literales para verificar reflexión, redacción y correlación.

Antes de usarla, valida la sintaxis:

```bash
python3 -c 'import yaml, pathlib; p=pathlib.Path("lab_demo_extraction_bypass_payloads.yaml"); d=yaml.safe_load(p.read_text()); assert d["lab_only"] is True; assert d["controls"]["require_loopback"] is True; print("lab-policy-ok", len(d["scenarios"]))'
```

## Presentación recomendada

Primero muestra el archivo YAML y explica la diferencia entre un **canario** y un payload de explotación: el canario no pretende cambiar el comportamiento del servidor; solo permite observar si el sistema lo refleja, lo almacena o lo procesa indebidamente. A continuación, ejecuta el escenario `access_bypass_simulation` y muestra que el actor sintético `viewer` recibe HTTP 403. Después ejecuta `extraction_simulation` y enseña que el registro es ficticio y que no contiene credenciales ni tokens.

Para la parte de inyección, ejecuta los escenarios uno por uno sobre la fixture local. La evidencia útil es el código HTTP, el cuerpo limitado, el hash de captura, la ausencia de cambios de estado y el hecho de que los canarios vuelven como texto. No muestres ni introduzcas cadenas de shell, operadores de consulta, etiquetas ejecutables, credenciales o identificadores de producción.

## Contrato de fixture local

La fixture debe devolver respuestas deterministas. Para `/demo/extraction`, responde con un JSON que contenga `DEMO_SYNTHETIC_RECORD_001`. Para `/demo/access-check` y `/demo/profile`, devuelve HTTP 403 para el actor `viewer`. Para `/demo/reflect`, devuelve el canario HTML-escaped o como texto, nunca como markup ejecutable. Para `/demo/utility`, registra internamente que no se creó ningún proceso. Para `/demo/regression`, devuelve todos los canarios como cadenas literales.

No hace falta que la fixture tenga base de datos, shell, LDAP real ni navegador. La demostración debe funcionar con respuestas estáticas y un registro local de eventos. Si se desea presentar la captura, conserva solamente un fragmento sintético y su SHA-256; redacta `Authorization`, `Cookie`, `Set-Cookie` y cualquier valor sensible.

## Findings y criterios de decisión

Cada escenario genera un finding con `status: candidate` y `requires_manual_review: true`. La etiqueta `confirmed_in_lab` solo significa que el control se reprodujo en la fixture; no prueba una vulnerabilidad en un sistema externo. Para elevar un finding en un pentest real se necesitarían autorización, alcance, evidencia reproducible, evaluación de impacto y revisión del propietario.

| Evidencia | Interpretación en laboratorio |
|---|---|
| HTTP 403 para actor `viewer` | Control de acceso negativo esperado. |
| Canario reflejado sin ejecución | La fixture trata la entrada como texto; no demuestra seguridad universal. |
| `process_spawned: false` | La prueba no ejecutó procesos. |
| `data_extraction: false` | No se recuperaron datos reales. |
| `state_change: false` | La prueba fue read-only. |
| SHA-256 persistido | Permite correlacionar la captura sin guardar todo el contenido. |

## Límites

No añadas a esta política `POST`, `PUT`, `PATCH`, `DELETE`, `--dump`, shells, callbacks, cargas de archivos, extracción de bases de datos, bypass de autenticación, credenciales reales ni payloads que modifiquen estado. Si una demostración requiere explicar uno de esos conceptos, usa diagramas, datos ficticios y resultados pregrabados, no una ejecución contra un servicio real.
