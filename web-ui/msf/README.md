# Metasploit — panel de Pent3stX (msfmcpd, MCP oficial)

Panel completo con exploits en **Tools → Metasploit (local)**, sobre
el MCP oficial de Metasploit, `msfmcpd`
([documentación oficial](https://docs.metasploit.com/docs/using-metasploit/other/how-to-use-metasploit-mcp-server.html)).
El backend (`web-ui/server.py`, solo stdlib) habla MCP JSON-RPC 2.0
por HTTP con `msfmcpd`; no instala ni arranca Metasploit, solo se
conecta al tuyo en local. La autorización es la casilla
"Confirmo que tengo autorización escrita para este alcance": sin
marcarla no se ejecuta nada, y no hay ningún campo de texto para
escribir una referencia.

## Qué hace

- **Lectura sin casilla**: buscar módulos (`msf_search_modules`),
  detalle de un módulo (`msf_module_info`), hosts / servicios /
  vulnerabilidades de la base de datos de Metasploit, sesiones
  activas (`msf_session_list`) y resultados de un job
  (`msf_module_results`).
- **Check y run solo con casilla**: `msf_module_check` y
  `msf_module_execute` son herramientas peligrosas de `msfmcpd` y
  están apagadas por defecto. Sin la casilla, el servidor responde
  409 sin llamar a Metasploit.
- **Detener sesiones solo con casilla**: `msf_session_stop`
  también es peligrosa y exige la misma casilla.
- **Flujo en dos pasos** (como Moodle): primero `/api/msf/plan`
  valida el módulo y sus opciones y muestra el plan exacto en la
  consola verde; luego el diálogo de confirmación con la casilla y
  después la ejecución. La ejecución usa el plan aprobado en
  memoria del servidor, no lo que llegue en la petición de run.

## Cómo arrancar Metasploit en tu PC

`msfmcpd` viene con Metasploit Framework. Desde la carpeta de
Metasploit (o con `msfmcpd` en el PATH):

```bash
# 1. RPC de Metasploit (si no lo arranca solo msfmcpd):
msfrpcd -U msfuser -P <tu-password> -p 55553

# 2. El servidor MCP oficial, transporte HTTP en 127.0.0.1:3000,
#    con las acciones peligrosas activadas:
./msfmcpd --mcp-transport http --enable-dangerous-actions
```

Sin `--enable-dangerous-actions` el panel solo lee: buscar módulos,
ver sesiones y consultar la base de datos funcionan, pero check,
run y detener sesiones responden 409 con el mensaje de activarlas.
Si `msfrpcd` ya corre, `msfmcpd` lo detecta y lo usa; si no, lo
arranca solo con credenciales aleatorias (ver la doc oficial).

El panel se conecta a `http://127.0.0.1:3000/` (variable de entorno
`MSF_MCP_URL` del servidor si quieres cambiarlo; solo se admiten
`127.0.0.1` y `localhost`). Si `msfmcpd` usa autenticación Bearer,
pon el token en la variable `MSF_MCP_AUTH_TOKEN` antes de arrancar
`server.py`, o pégalo en el campo password del diálogo: vive solo
en memoria, nunca se guarda en disco, en el repo ni en logs, y
nunca aparece en un manifiesto.

Base de datos (opcional, para hosts/servicios/vulns):

```bash
msfdb init
msfdb start
```

## Guardrails (los aplica el servidor, no la página)

- **Target**: `RHOST`/`RHOSTS` solo aceptan `contaia.site` y
  `127.0.0.1`, sin resolver DNS, sin CIDR, sin privadas, sin
  `file:`. Cualquier otro target se rechaza (400 en el plan,
  409 en la ejecución).
- **LHOST solo `127.0.0.1`**: el handler escucha en loopback y
  nada más. `0.0.0.0`, IPs públicas o nombres se rechazan.
- **Opciones validadas** como en la doc oficial: claves con forma
  de opción de Metasploit (segmentos unidos por `::` o `-`),
  máximo 100 claves, valores simples, strings de 8 KB como máximo,
  64 KB en total. `RPORT`/`LPORT`/`SRVPORT` deben ser puertos
  1–65535.
- **Acciones peligrosas**: el panel lee `tools/list` de `msfmcpd`
  y muestra si están activadas. Si están desactivadas, check/run/
  stop responden 409 antes de llamar a Metasploit.
- **Secretos redactados**: las opciones con pinta de secreto
  (`*password*`, `*token*`, `*secret*`, `*key*`, `*cookie*`)
  se guardan como `***` en el manifiesto; el token MCP no se
  guarda nunca.

## Payloads reverse y el handler

**Decisión implementada: el handler va por la misma conexión MCP,
no se abre una segunda conexión.**

Cuando el plan lleva un payload reverse (`PAYLOAD` con "reverse",
p. ej. `windows/meterpreter/reverse_tcp`), el panel no deja el
handler al aire: antes del exploit, el backend ejecuta
`exploit/multi/handler` como job en segundo plano con
`msf_module_execute`, con el mismo payload, `LHOST` 127.0.0.1,
`LPORT` y `ExitOnSession: false`. Después corre el exploit, y
luego busca la sesión entrante en `msf_session_list` y la vincula
a esa ejecución (por módulo, payload, target y puerto del túnel);
la sesión aparece en la tabla de sesiones del panel.

Por qué basta una sola conexión: el handler es un job del
framework (msfrpcd), no de la conexión MCP. Las llamadas MCP son
JSON-RPC sin estado: la petición que arranca el handler termina y
el listener sigue vivo en Metasploit. No hace falta sostener una
conexión persistente ni abrir otra dedicada al handler; una segunda
conexión no añadiría nada (las 16 herramientas son las mismas en
cualquier conexión, y ninguna lista ni detiene jobs).

Consecuencias que hay que conocer:

- **El handler sigue escuchando después de la ejecución**
  (`ExitOnSession: false`). Si vuelves a lanzar el mismo payload
  en el mismo puerto, el panel reutiliza el handler ya arrancado
  en vez de arrancar un duplicado (lo registra en memoria del
  servidor; el estado del panel lo muestra en
  `/api/msf/status` como `handlers`).
- **No hay herramienta MCP para detener un job**: `msfmcpd` no
  expone `job.stop`. Para parar el handler, usa msfconsole:
  `jobs` para verlo y `jobs -K <id>` para matarlo. El panel sí
  puede detener las *sesiones* (botón Detener, con casilla).
- **Si el servidor se reinicia**, el registro de handlers se
  pierde: un segundo arranque del mismo handler fallará con el
  error del framework (puerto en uso) y el panel lo mostrará; en
  ese caso para el handler viejo en msfconsole y vuelve a
  intentarlo.
- **Defaults explícitos**: un payload reverse sin `LHOST` recibe
  `127.0.0.1`, y sin `LPORT` recibe `4444` (los defaults de
  Metasploit para `reverse_tcp`). El plan que confirmas los
  muestra y los anota; nunca se aplican en silencio.
- Un payload `bind_tcp` (sin "reverse") no arranca handler.

## API del backend

- `GET /api/msf/status` y `POST /api/msf/status` — `{connected,
  url, dangerous_actions, tools, handlers}`. El POST acepta
  `mcp_token` para probar la conexión con el token del diálogo.
- `POST /api/msf/search` — `{query, limit?, mcp_token?}`.
  Devuelve `{connected, modules}`.
- `GET /api/msf/modules?type=&q=` — búsqueda por tipo y término.
- `POST /api/msf/module-info` — `{type, name, mcp_token?}`.
- `GET /api/msf/hosts|services|vulns?workspace=default` — datos
  de la base de datos de Metasploit.
- `GET /api/msf/sessions` — sesiones activas.
- `GET /api/msf/result?uuid=` — resultado de un job por su UUID.
- `POST /api/msf/plan` — `{type, name, action: check|run,
  options, mcp_token?}`. Valida y devuelve el plan exacto
  (módulo, opciones redactadas, si es reverse, el handler que
  necesita y las notas de defaults) más la info del módulo si
  `msfmcpd` está conectado. No ejecuta nada.
- `POST /api/msf/check` y `POST /api/msf/run` — `{confirm: true,
  confirm_written_authorization, mcp_token?}`. Exigen plan
  aprobado de esa misma acción y la casilla marcada; sin casilla,
  409; con las acciones peligrosas desactivadas, 409 con el
  mensaje de `--enable-dangerous-actions`. El run con payload
  reverse arranca antes el handler (o reutiliza el existente).
- `POST /api/msf/session/stop` — `{confirm: true,
  confirm_written_authorization, session_id, mcp_token?}`.
  Exige la casilla.

## Evidencia

Cada check, run y stop de sesión guarda un manifiesto en
`workspace/msf_runs/<timestamp>/manifest.json`: módulo, acción,
opciones **redactadas**, si era reverse, el handler (uuid, job,
LHOST, LPORT, payload, reutilizado o no), el resultado resumido
y las sesiones vinculadas. El token MCP y los secretos de las
opciones no aparecen nunca.

## Archivos

- `web-ui/msf/msf_client.py` — cliente MCP (JSON-RPC 2.0 por
  HTTP, solo stdlib) + validación de módulos, opciones, targets,
  LHOST y planes reverse con su handler.
- `web-ui/msf/README.md` — este archivo.
- `web-ui/test_msf.py` — 32 tests contra un mock propio de
  `msfmcpd` (32 en verde): validación, handler antes del exploit,
  sesión vinculada, reutilización del handler, 409 sin casilla,
  409 con target fuera de alcance, 409 con acciones peligrosas
  desactivadas, token nunca en el manifiesto.
- `web-ui/server.py` — endpoints `/api/msf/*` y evidencia en
  `workspace/msf_runs/`.

## Qué NO hace

- No instala ni arranca Metasploit, `msfrpcd` ni `msfmcpd`: eso
  se hace en tu PC (ver arriba).
- No inventa módulos, resultados ni sesiones: sin conexión con
  `msfmcpd`, la búsqueda devuelve lista vacía y el panel lo dice.
- No usa `msf_session_write` (escribir en sesiones interactivas):
  el panel no la expone.
- No toca `pentestx.py` ni `pentestx_controlled.py`.
