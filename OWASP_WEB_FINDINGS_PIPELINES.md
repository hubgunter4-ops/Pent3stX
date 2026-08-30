# PentestX — OWASP Web Findings, Pipelines y Políticas YAML

## Propósito y alcance

Este documento describe el módulo `owasp_web` de `pentestx.py`, el formato de findings que genera, los pipelines correlacionados y diez ejemplos de perfiles YAML. El módulo está alineado con **OWASP Top 10:2025**, cuya lista oficial contiene A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures y A10 Mishandling of Exceptional Conditions [1].

La etiqueta **intrusivo** se utiliza aquí para indicar que el perfil realiza solicitudes HTTP/HTTPS activas dentro del alcance confirmado. Los perfiles incluidos son deliberadamente no destructivos: solo permiten `GET` y `HEAD`, deshabilitan redirecciones automáticas, limitan la tasa, el número de URLs, el número total de solicitudes y el tamaño de respuesta, y no envían payloads, credenciales, cambios de estado ni interacciones fuera de banda. Los resultados son candidatos basados en evidencia y requieren revisión humana conforme a las reglas de compromiso.

> La persistencia de este módulo es local: conserva findings, observaciones, hashes y manifiestos en el workspace de la sesión. No crea persistencia en el target evaluado.

## Uso rápido

Lista los perfiles incluidos y los cargados desde una política YAML:

```bash
python3 pentestx.py --list-owasp-profiles
```

Ejecuta una previsualización sin solicitudes de red sobre un dominio o URL autorizado:

```bash
python3 pentestx.py \
  --target https://app.example.com/login \
  --scope active \
  --action owasp_web \
  --owasp-profile owasp_web_intrusive \
  --confirm-written-authorization \
  --dry-run
```

Carga los diez perfiles de ejemplo:

```bash
python3 pentestx.py \
  --owasp-policy-file owasp_profiles.example.yaml \
  --list-owasp-profiles
```

La ejecución real requiere un target dentro del alcance, `--scope active` y `--confirm-written-authorization`. No uses una URL o dominio de terceros sin autorización escrita y vigente.

## Clasificación y origen de targets

El módulo acepta una URL HTTP/HTTPS, un dominio o una IP individual. Para un dominio o IP se construye una URL HTTPS base. Si `findings_db.json` contiene URLs HTTP/HTTPS dentro del mismo host raíz o subdominios autorizados, estas se incorporan hasta `max_urls`; las URLs fuera de esa raíz se descartan. Un CIDR no se acepta como target web directo porque requiere una selección explícita de hosts y URLs.

La fuente de findings se resuelve en este orden: `--findings-file`, findings de la sesión actual y, finalmente, el `findings_db.json` más reciente del workspace. Los findings sirven para descubrir URLs autorizadas y para correlacionar resultados; no convierten por sí solos un target en autorizado.

## Modelo de findings

Cada candidato se guarda con una estructura similar a la siguiente:

```json
{
  "owasp_id": "A02",
  "title": "Security Misconfiguration",
  "check": "security_headers",
  "severity": "low",
  "confidence": "medium",
  "status": "candidate",
  "url": "https://app.example.com/",
  "method": "HEAD",
  "evidence": {
    "missing_headers": ["content-security-policy"],
    "status": 200
  },
  "recommendation": "Definir cabeceras de seguridad apropiadas.",
  "requires_manual_validation": true
}
```

El escaneo también conserva observaciones reducidas: código HTTP, método, latencia, tamaño de cuerpo, error de transporte y SHA-256 del cuerpo. No almacena valores de `Set-Cookie`, `Authorization` ni `Proxy-Authorization`; estos se redactan. Las salidas principales son `owasp_web/owasp_findings.json`, `owasp_web/OWASP_WEB_REPORT.md` y `owasp_web/capture_manifest.json`.

## Mapa de checks

| OWASP | Check externo | Evidencia limitada | Resultado esperado |
|---|---|---|---|
| A01 | `access_boundary_review` | Rutas con indicadores administrativos o internos observadas en URLs autorizadas. | Candidato de revisión; la alcanzabilidad no demuestra autorización. |
| A02 | `security_headers` | Ausencia de CSP, X-Content-Type-Options o Referrer-Policy. | Candidato de configuración. |
| A03 | `supply_chain_metadata` | Indicadores de source maps o artefactos de desarrollo en respuestas públicas. | Candidato de revisión de build/provenance. |
| A04 | `tls_cookie_baseline` | Servicio accesible por HTTP sin cifrado de transporte. | Candidato de transporte inseguro. |
| A05 | `injection_error_signals` | Mensajes de error conocidos en una respuesta ordinaria; no se envían payloads. | Señal débil que exige validación manual. |
| A06 | `method_surface` | Respuestas 5xx o superficies de método observadas con GET/HEAD. | Candidato de revisión de diseño y fallos. |
| A07 | `auth_cookie_baseline` | Flags `Secure`, `HttpOnly` o `SameSite` ausentes en cookies observadas. | Candidato de configuración de sesión. |
| A08 | `integrity_metadata` | Referencias a source maps o metadatos de artefactos expuestos. | Candidato de integridad/publicación. |
| A09 | `logging_error_surface` | Superficie de errores 5xx que requiere comprobar logging y alertas. | Candidato de revisión operativa. |
| A10 | `exception_handling` | Respuestas 4xx/5xx o indicadores de stack trace/exception. | Candidato de manejo seguro de excepciones. |

La detección es heurística. Un estado `candidate` nunca debe elevarse automáticamente a `confirmed` sin comprobar la política del programa, el activo, la evidencia y el impacto con una variante aprobada.

## Pipelines correlacionados

El pipeline `with_owasp` combina reconocimiento, revisión web y el módulo OWASP:

```text
passive → active → web → owasp_web → vulnerability → correlate → report
```

El pipeline `full_web` añade enumeración de puertos, vulnerabilidades e intrusivo controlado:

```text
passive → active → ports → web → owasp_web → vuln → intrusive → vulnerability → correlate → report
```

Previsualiza el pipeline OWASP sin tráfico:

```bash
python3 pentestx.py \
  --target 192.0.2.10 \
  --scope active \
  --action correlated \
  --pipeline-profile with_owasp \
  --owasp-profile owasp_web_intrusive \
  --confirm-written-authorization \
  --dry-run
```

Desde `--interactive`, el flujo dispone de una acción dedicada para añadir el escaneo OWASP y de una selección de perfil. El menú persistente se dibuja una vez; la selección del perfil y los datos del plan solo actualizan el dashboard.

## Diez ejemplos YAML intrusivos controlados

Los siguientes perfiles son compatibles con el validador de `pentestx.py`. Cada ejemplo representa una categoría OWASP. El esquema no acepta `command`, binarios arbitrarios, payloads, cabeceras de autenticación, métodos mutantes, redirecciones automáticas ni llamadas fuera de la allowlist.

### 1. A01 — Broken Access Control

```yaml
profiles:
  owasp_a01_access_control:
    owasp_version: "2025"
    checks: [A01]
    rate_limit: 2
    timeout: 10
    max_urls: 10
    max_requests: 20
    methods: [GET]
    follow_redirects: false
    body_limit: 32768
```

Este perfil solo identifica rutas sensibles que ya aparecen en URLs autorizadas y las marca para revisión con cuentas de prueba. No intenta saltarse controles ni acceder a datos reales.

### 2. A02 — Security Misconfiguration

```yaml
profiles:
  owasp_a02_misconfiguration:
    owasp_version: "2025"
    checks: [A02]
    rate_limit: 3
    timeout: 10
    max_urls: 20
    max_requests: 40
    methods: [HEAD, GET]
    follow_redirects: false
    body_limit: 16384
```

Revisa cabeceras de seguridad en respuestas públicas. El análisis no modifica la configuración del servidor.

### 3. A03 — Software Supply Chain Failures

```yaml
profiles:
  owasp_a03_supply_chain:
    owasp_version: "2025"
    checks: [A03]
    rate_limit: 2
    timeout: 10
    max_urls: 10
    max_requests: 20
    methods: [GET]
    follow_redirects: false
    body_limit: 65536
```

Busca indicadores de artefactos de desarrollo o metadata de build expuestos. No descarga dependencias ni ejecuta código.

### 4. A04 — Cryptographic Failures

```yaml
profiles:
  owasp_a04_crypto:
    owasp_version: "2025"
    checks: [A04]
    rate_limit: 2
    timeout: 10
    max_urls: 10
    max_requests: 20
    methods: [HEAD, GET]
    follow_redirects: false
    body_limit: 16384
```

Identifica endpoints HTTP y genera un candidato para verificar la política de transporte seguro en el endpoint HTTPS correspondiente.

### 5. A05 — Injection

```yaml
profiles:
  owasp_a05_injection_signals:
    owasp_version: "2025"
    checks: [A05]
    rate_limit: 1
    timeout: 10
    max_urls: 10
    max_requests: 10
    methods: [GET]
    follow_redirects: false
    body_limit: 65536
```

Solo analiza mensajes de error presentes en respuestas ordinarias. No genera payloads SQL, XSS, LDAP, comandos ni parámetros modificados.

### 6. A06 — Insecure Design

```yaml
profiles:
  owasp_a06_insecure_design:
    owasp_version: "2025"
    checks: [A06]
    rate_limit: 2
    timeout: 10
    max_urls: 10
    max_requests: 20
    methods: [GET]
    follow_redirects: false
    body_limit: 32768
```

Registra superficies de error para priorizar revisión del modelo de amenazas y de los requisitos de seguridad. No intenta modificar estados de negocio.

### 7. A07 — Authentication Failures

```yaml
profiles:
  owasp_a07_authentication:
    owasp_version: "2025"
    checks: [A07]
    rate_limit: 2
    timeout: 10
    max_urls: 10
    max_requests: 20
    methods: [HEAD, GET]
    follow_redirects: false
    body_limit: 16384
```

Revisa flags de cookies que el servidor exponga en respuestas públicas o de prueba. No realiza login, guessing, replay ni bypass.

### 8. A08 — Software or Data Integrity Failures

```yaml
profiles:
  owasp_a08_integrity:
    owasp_version: "2025"
    checks: [A08]
    rate_limit: 2
    timeout: 10
    max_urls: 10
    max_requests: 20
    methods: [GET]
    follow_redirects: false
    body_limit: 65536
```

Busca referencias de source maps y metadata de publicación para revisión del proceso de build. No manipula artefactos.

### 9. A09 — Security Logging and Alerting Failures

```yaml
profiles:
  owasp_a09_logging:
    owasp_version: "2025"
    checks: [A09]
    rate_limit: 2
    timeout: 10
    max_urls: 10
    max_requests: 20
    methods: [GET]
    follow_redirects: false
    body_limit: 32768
```

Marca superficies de error que deben contrastarse con logs y alertas del propietario. No intenta provocar cargas, inundaciones ni eventos de disponibilidad.

### 10. A10 — Mishandling of Exceptional Conditions

```yaml
profiles:
  owasp_a10_exceptions:
    owasp_version: "2025"
    checks: [A10]
    rate_limit: 2
    timeout: 10
    max_urls: 10
    max_requests: 20
    methods: [GET]
    follow_redirects: false
    body_limit: 32768
```

Observa respuestas de error y posibles indicadores de excepciones para recomendar respuestas genéricas y logging protegido. No fuerza condiciones excepcionales mediante payloads.

## Validación de la política

Guarda los diez perfiles en `owasp_profiles.example.yaml` y valida la carga antes de cualquier ejecución:

```bash
python3 pentestx.py \
  --owasp-policy-file owasp_profiles.example.yaml \
  --list-owasp-profiles
```

Para revisar un perfil y un target autorizado sin tráfico:

```bash
python3 pentestx.py \
  --target https://app.example.com/ \
  --scope active \
  --action owasp_web \
  --owasp-policy-file owasp_profiles.example.yaml \
  --owasp-profile owasp_a05_injection_signals \
  --confirm-written-authorization \
  --dry-run
```

Las claves desconocidas, como `payloads`, `command`, `headers`, `auth`, `post_data`, `shell` o `follow_redirects: true`, deben ser rechazadas antes de cualquier solicitud. La primera ejecución real debe mantener el perfil más pequeño, revisar el manifiesto y confirmar que las URLs proceden del alcance autorizado.

## Artefactos y trazabilidad

Cada sesión conserva el perfil, la versión OWASP, checks, URLs planeadas, solicitudes realizadas, códigos de estado, latencias, hashes, findings, timestamp, estado y ruta de los informes. Los cuerpos completos no se incluyen en el manifiesto; solo se conserva un fragmento limitado durante la evaluación y un SHA-256 para correlación local.

## Referencias

[1]: https://owasp.org/Top10/2025/en/ — OWASP Top 10:2025, lista oficial y categorías.

[2]: https://owasp.org/www-project-web-security-testing-guide/ — OWASP Web Security Testing Guide, marco de pruebas de aplicaciones web y servicios.

[3]: https://owasp.org/www-project-top-ten/ — Proyecto oficial OWASP Top Ten y versiones históricas.
