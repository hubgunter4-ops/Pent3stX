# Moodle SQLi — herramienta aparte de Pent3stX

Sonda de inyección SQL ciega basada en tiempo contra un Moodle
local, como script aparte en `web-ui/tools/`. **No toca
`pentestx.py` ni `pentestx_controlled.py`**: la CLI principal sigue
sin exponer explotación; esta herramienta vive separada, con sus
propios guardrails, y solo se usa desde la web-ui (menú Tools) o
directo por CLI.

> **Uso autorizado únicamente.** Solo para el Moodle propio del
> laboratorio (`http://127.0.0.1:8080/moodle`), cubierto por
> autorización escrita. No es para ningún otro Moodle ni ningún
> otro host.

## Qué hace

1. **Detección:** envía una sonda `fullname OR SLEEP(n)` al
   webservice `core_course_get_enrolled_courses_by_timeline_classification`
   (`lib/ajax/service.php`). Si la respuesta tarda al menos `n`
   segundos, la inyección en `sort` se evalúa y el objetivo es
   vulnerable. Es el PoC público de Julio Ángel Ferrari (T0X1Cx)
   para **CVE-2021-36393** (MSA-21-0021, CVSS 9.8; Moodle 3.9/3.10/3.11
   vulnerables, corregido en 3.9.8, 3.10.5 y 3.11.1).
2. **Extracción, carácter por carácter:** si es vulnerable, prueba
   cada carácter del alfabeto con
   `fullname OR (database()) LIKE 'X%' AND SLEEP(n)` y con
   `(SELECT username FROM mdl_user LIMIT 1 OFFSET 0) LIKE 'X%' AND
   SLEEP(n)`. Un retardo ≥ `n` segundos significa que el carácter
   acertó.

## Qué NO hace

- **No extrae `password`:** la columna `password` de `mdl_user`
  (el hash guardado) quedó fuera a propósito. `--extract` solo
  acepta `database` y `username`, y el servidor rechaza `password`.
  Solo se añadiría si Robert lo pide explícitamente.
- No toca ningún otro host, puerto o ruta: `--base-url` debe ser
  exactamente `http://127.0.0.1:8080/moodle`.
- No guarda la sesión: la cookie `MoodleSession` y el `sesskey`
  solo viven en memoria durante la ejecución. La evidencia guarda
  únicamente su SHA-256 y su longitud, nunca el valor.

## Requisitos

- Moodle corriendo en local en `http://127.0.0.1:8080/moodle`.
- Una sesión válida y vigente: el `sesskey` y el valor de la
  cookie `MoodleSession` se sacan del navegador con la sesión
  iniciada (herramientas de desarrollo → Application/Storage →
  Cookies, o la URL de `service.php` en la pestaña Network). Caducan:
  si la sonda de detección no da retardo, lo primero es revisar
  que la sesión siga vigente.
- Solo la librería estándar de Python 3: sin `requests` ni
  `termcolor`.
- Autorización escrita: `--confirm-written-authorization` y
  `--authorization-reference` son obligatorios para ejecutar.

## Uso por CLI

Desde la raíz del repositorio:

```bash
# Ver los payloads exactos sin enviar nada
python3 web-ui/tools/moodle_sqli.py --dry-run

# Detectar y extraer database() y username del primer usuario
python3 web-ui/tools/moodle_sqli.py \
  --sesskey <sesskey-vigente> \
  --session-cookie <valor-MoodleSession-vigente> \
  --extract database username \
  --confirm-written-authorization \
  --authorization-reference docs/AUTORIZACION-moodle-local.md
```

Opciones: `--sleep` (segundos de SLEEP, defecto 3, 1–10),
`--timeout` (timeout HTTP, defecto 15), `--max-chars` (máximo 50
caracteres por valor). La salida es JSON por stdout (resultado,
`vulnerable`, `results`, peticiones enviadas y directorio de
evidencia); el progreso va por stderr. La evidencia queda en
`workspace/moodle_sqli/<timestamp>/manifest.json`, con el comando
exacto (secretos redactados) y los resultados.

## Uso desde la web-ui

Menú **Tools → Moodle SQLi (local)**: pide base-url, sesskey,
cookie de sesión, qué extraer (database / username) y la referencia
de autorización. Flujo: dry-run → muestra los payloads en la
consola → confirmación → ejecución → salida real en la consola
verde. Sin backend, la entrada queda deshabilitada y no simula nada.

## API del backend

- `POST /api/tools/moodle-sqli/dry-run` — valida y devuelve los
  payloads exactos sin enviar nada. Requiere referencia de
  autorización.
- `POST /api/tools/moodle-sqli/run` — `{confirm: true,
  authorization_reference}`. Solo con dry-run previo del comando
  exacto y la misma referencia; si no, 409 sin ejecutar.

## Tests

```bash
python3 -m py_compile web-ui/tools/moodle_sqli.py
python3 -m unittest discover -s web-ui/tools -p "test_moodle_sqli.py" -v
```

Los tests no contactan un Moodle real: la prueba de extracción
corre contra un mock HTTP propio en 127.0.0.1:8080 que responde
lento solo cuando el carácter probado acierta, y la prueba de
dry-run verifica que no se envía ninguna petición.
