# Pent3stX Workbench — nueva interfaz web (Design Option 1)

Interfaz web autónoma que reproduce el diseño 1 estilo Ettercap clásico
elegido por Robert. **Sustituye a la GUI original de Tkinter
(`pentestx_gui.py`), que fue eliminada del repositorio.** La lógica de
evaluación real sigue viviendo en la CLI (`pentestx.py`); esta página
solo muestra y simula el flujo en local.

> **Uso autorizado únicamente.** Solo para activos propios o cubiertos
> por autorización escrita y reglas de compromiso vigentes. La página
> es de solo lectura: **no genera tráfico de red ni ejecuta escaneos
> reales**. La ejecución real se hace con `pentestx.py` en el
> laboratorio, nunca desde esta página.

## Cómo abrirla

No necesita servidor ni instalación. Solo abre el archivo en el
navegador:

- Haz doble clic en `web-ui/index.html`, o arrástralo a una ventana del
  navegador.

No hay dependencias: son tres archivos (`index.html`, `styles.css`,
`app.js`) y esta guía. Funciona sin conexión.

## Qué se ve en cada zona

- **Barra de título:** `Pent3stX Workbench — Design Option 1 —
  Authorized Security Assessment (Read-Only / Authorized Assessment
  Only)`. Los botones de ventana son decorativos: en una página web
  no se puede minimizar ni cerrar la ventana del sistema, y al
  pulsarlos la consola lo explica.
- **Menú:** File, Edit, View, Tools, Assessments, Plugins, Window y
  Help. Cada opción abre su menú y hace algo visible (por ejemplo,
  `File → Export report…` descarga el reporte, `Help → About`
  muestra la ventana de información).
- **Barra de herramientas:** New, Open, Start, Pause, Scan, Import,
  Export, Save y Config, con el distintivo `Authorized • Assessment
  Only` a la derecha.
- **OPERATIONS • PHASES (izquierda):** árbol de fases — `passive`
  (discovery, passive-recon), `active` (host-probe), `web` (crawl),
  `ports` (portscan), `vuln` (vuln-scan), `owasp_web` (owasp-zap,
  seleccionada por defecto), `correlate` (correlation) y `report`
  (generate-report). Al pie: `Profiles: 3 active • Ruleset: OWASP v4`.
  Pulsar una fase la selecciona y lo anota en la consola.
- **Session Map (centro):** sesión `SA-2024-011`, 4 hosts y 3
  servicios, solo lectura. Nodos: `srv-web-01 (10.10.50.10) http:80`,
  `srv-api-02 (10.10.50.11) api:443`, `db-01 (10.10.50.20)
  postgres:5432` y `fw-gateway (10.10.50.1) firewall`, dentro del
  ámbito autorizado confirmado por el cliente. Pulsar un nodo lo
  selecciona y lo anota en la consola.
- **Plan Overview (centro):** la otra pestaña central. Muestra el
  plan (passive → active → OWASP Web Scan → correlation → report) y
  la fase seleccionada.
- **Tabla de tareas (centro, debajo del mapa):** Passive Recon
  (Completed), Portscan (TCP) (Completed), OWASP Web Scan (Running,
  analyst-02) y Correlation (Pending, a la espera de los resultados
  OWASP).
- **INSPECTOR (derecha):** pestañas Pipeline, Profiles y Findings.
  Pipeline Status: step1 Passive Completed 13:20 UTC, step2 Active
  Completed 13:45 UTC, step3 Web Scan Running (48%), OWASP ZAP
  12/25 checks, con barra de progreso. Profiles: OWASP Web Standard
  v4 y Portscan Default, ambos Enabled. Findings (7): se muestran
  los 3 del diseño — [MED] Outdated Server Header (srv-web-01:80,
  CWE-1008), [LOW] TLS 1.0 Supported (srv-api-02:443, CWE-326) y
  [INFO] Open DB Port Detected (db-01:5432, solo interno).
- **TERMINAL CONSOLE (abajo, fija):** consola verde con las líneas
  de log de la sesión. Se puede colapsar con el botón ▭ y limpiar
  con Clear. Debajo, la barra verde: `Ready | Authorized Assessment
  Only — Approved Scope: 10.10.50.0/24`.
- **Barra de estado (pie):** `Session: SA-2024-011 | Hosts: 4 |
  Services: 5 | Findings: 7 | Warnings: 1` y `User: sec-analyst |
  2024-11-25 14:32:08 UTC | v1.2.0-design1`.

## Cómo usarla

1. **Elegir fase:** pulsa una fase del árbol de la izquierda. Queda
   resaltada en azul y la consola anota la selección.
2. **Start / Pause:** `Start` (o `Scan`) avanza la simulación local
   del escaneo OWASP: el contador sube de 12/25 en adelante, la
   barra de progreso y el porcentaje (48 % al inicio) avanzan, y la
   consola añade una línea por cada check. `Pause` detiene el
   avance. Al llegar a 25/25, el escaneo pasa a Completed y
   Correlation pasa a Running. No se contacta ningún host.
3. **New:** reinicia la vista local a los valores del diseño (12/25
   checks, 48 %).
4. **Open / Import:** abren un selector de archivos del navegador
   para cargar un archivo local (hasta 1 MiB) y tratarlo solo como
   datos: la consola muestra su nombre, tamaño y número de líneas.
   El archivo no se ejecuta.
5. **Export:** descarga `pent3stx-SA-2024-011-report.json` con la
   sesión, el ámbito, la fase, el progreso y los findings visibles.
6. **Save:** guarda el estado actual (checks y fase) en el
   almacenamiento local del navegador; al volver a abrir la página
   se restaura.
7. **Config:** abre el diálogo de configuración: ámbito aprobado
   (solo lectura), opción de reducir animaciones y de mantener la
   consola fija abajo.
8. **View:** `Toggle terminal console` colapsa o muestra la consola,
   `Toggle inspector` oculta o muestra el panel derecho, y `Reset
   layout` (menú Window) devuelve el diseño a sus valores por
   defecto.

## Qué NO hace esta página

- No escanea, no resuelve nombres, no abre puertos y no envía nada
  por la red.
- No ejecuta `pentestx.py`, Nmap, ZAP ni ninguna herramienta.
- Los datos que muestra (sesión SA-2024-011, hosts 10.10.50.x,
  findings) son los del diseño elegido, no resultados de una
  evaluación real.
- No sustituye la autorización escrita: la confirmación en la
  interfaz no es autorización del propietario del activo.

## Archivos

- `web-ui/index.html` — estructura de la interfaz.
- `web-ui/styles.css` — estilos del diseño Ettercap clásico.
- `web-ui/app.js` — comportamiento local (simulación, menús,
  pestañas, consola, guardar/exportar).
- `web-ui/README.md` — esta guía.
