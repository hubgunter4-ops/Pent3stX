/* Pent3stX Workbench — Design Option 1 (functional mode).
   No simulation: every Start goes through the local backend
   (http://127.0.0.1:8765/, web-ui/server.py), which validates the
   request and calls the real pentestx.py CLI — dry-run first, then
   execution only after explicit confirmation of the exact command.
   Without the backend running, Start/Scan do nothing and the UI says
   so. Console, Inspector, tasks and findings only show real data
   returned by the backend. */
(function () {
  "use strict";

  var API = "";
  var PHASE_ACTIONS = {
    passive: ["passive"], discovery: ["passive"], "passive-recon": ["passive"],
    active: ["active"], "host-probe": ["active"],
    web: ["web"], crawl: ["web"],
    ports: ["ports"], portscan: ["ports"],
    vuln: ["vuln"], "vuln-scan": ["vuln"],
    owasp_web: ["owasp_web"], "owasp-zap": ["owasp_web"],
    correlate: ["correlate"], correlation: ["correlate"],
    report: ["report"], "generate-report": ["report"]
  };

  var state = {
    connected: false,
    pentestxPresent: false,
    running: false,
    phase: "owasp_web",
    plan: null,
    sessionDir: null,
    moodleRequest: null,
    enginePlan: null,
    msfPlan: null,
    msfAction: null,
    msfPendingStop: null,
    msfConnected: false,
    msfDangerous: null,
    msfSelected: null,
    config: {
      target: "contaia.site",
      scope: "passive",
      pipeline_profile: "with_owasp"
    }
  };

  var consoleBody = document.getElementById("consoleBody");
  var fileInput = document.getElementById("fileInput");

  function stamp() {
    var d = new Date();
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return "[" + d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) +
      " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds()) + "] ";
  }

  function log(msg) {
    consoleBody.textContent += "\n" + stamp() + msg;
    consoleBody.scrollTop = consoleBody.scrollHeight;
  }

  function logLines(text) {
    if (!text) return;
    var lines = String(text).split(/\n/).slice(0, 500);
    lines.forEach(function (line) {
      if (line.trim() !== "") consoleBody.textContent += "\n" + line;
    });
    consoleBody.scrollTop = consoleBody.scrollHeight;
  }

  function api(path, options, timeoutMs) {
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, timeoutMs || 30000);
    var init = { signal: controller.signal, headers: { "Content-Type": "application/json" } };
    if (options) {
      init.method = options.method || "GET";
      if (options.body !== undefined) init.body = JSON.stringify(options.body);
    }
    return fetch(API + path, init).then(function (res) {
      clearTimeout(timer);
      return res.json().then(function (data) {
        if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
        return data;
      });
    }).catch(function (err) {
      clearTimeout(timer);
      throw err;
    });
  }

  function setStartEnabled(enabled) {
    document.querySelectorAll('[data-action="start"], [data-action="scan"]').forEach(function (b) {
      b.disabled = !enabled;
      b.classList.toggle("disabled", !enabled);
    });
  }

  function renderBackend() {
    var green = document.getElementById("statusGreen");
    if (state.connected && state.pentestxPresent) {
      green.textContent = "Backend conectado — pentestx.py disponible. Listo para dry-run.";
    } else if (state.connected) {
      green.textContent = "Backend conectado, pero pentestx.py no está en la raíz del repo.";
    } else {
      green.textContent = "Backend no conectado — arranca python3 web-ui/server.py";
    }
    setStartEnabled(state.connected && state.pentestxPresent && !state.running);
    document.querySelectorAll('[data-action="moodle-sqli"]').forEach(function (b) {
      b.disabled = !(state.connected && !state.running);
      b.classList.toggle("disabled", b.disabled);
    });
    document.querySelectorAll('[data-action="msf"]').forEach(function (b) {
      b.disabled = !(state.connected && !state.running);
      b.classList.toggle("disabled", b.disabled);
    });
    document.querySelectorAll('[data-action="engine-plan"]').forEach(function (b) {
      b.disabled = !(state.connected && !state.running);
      b.classList.toggle("disabled", b.disabled);
    });
  }

  function checkBackend() {
    return api("/api/status", null, 5000).then(function (data) {
      state.connected = true;
      state.pentestxPresent = !!data.pentestx_present;
      if (state.pentestxPresent) {
        log("[+] Backend conectado en 127.0.0.1:8765. pentestx.py disponible.");
      } else {
        log("[!!] Backend conectado, pero pentestx.py no está en " + (data.repo_root || "") + ".");
      }
      renderBackend();
      return loadSessions();
    }).catch(function () {
      state.connected = false;
      state.pentestxPresent = false;
      log("[!!] Backend no conectado — arranca: python3 web-ui/server.py (desde la raíz del repo) y recarga la página. Start está deshabilitado; no se simula nada.");
      renderBackend();
    });
  }

  function loadSessions() {
    return api("/api/sessions").then(function (data) {
      var sessions = data.sessions || [];
      if (!sessions.length) {
        log("[*] Sin sesiones todavía en workspace/pentestx_sessions/.");
        return;
      }
      var latest = sessions[0];
      state.sessionDir = latest.name;
      document.getElementById("statusSession").textContent =
        "Session: " + latest.name + " | Sin datos de hosts (ver Findings)";
      document.getElementById("mapHeader").textContent =
        "Session: " + latest.name + " | Map View • Datos reales de la sesión";
      log("[*] Última sesión real: " + latest.name + " (manifiesto: " + (latest.manifest ? "sí" : "no") + ", findings: " + (latest.findings ? "sí" : "no") + ").");
      return loadFindings(latest.name);
    }).catch(function (err) {
      log("[!!] No se pudieron listar las sesiones: " + err.message);
    });
  }

  function findingText(f) {
    if (f && typeof f === "object") {
      var title = f.title || f.name || f.finding || f.id || JSON.stringify(f);
      var sev = f.severity || f.risk || "";
      var target = f.target || f.host || f.url || "";
      var cwe = f.cwe || f.cwe_id || "";
      return [sev ? "[" + String(sev).toUpperCase() + "]" : "", title, target, cwe]
        .filter(Boolean).join(" — ");
    }
    return String(f);
  }

  function renderFindings(findings) {
    var title = document.getElementById("findingsTitle");
    if (title) title.textContent = "FINDINGS (" + findings.length + ")";
    ["findingsList", "findingsListAlways"].forEach(function (id) {
      var ul = document.getElementById(id);
      if (!ul) return;
      ul.innerHTML = "";
      if (!findings.length) {
        var li = document.createElement("li");
        li.textContent = "Sin findings en esta sesión.";
        ul.appendChild(li);
        return;
      }
      findings.forEach(function (f) {
        var item = document.createElement("li");
        item.textContent = findingText(f);
        ul.appendChild(item);
      });
    });
  }

  function loadFindings(sessionName) {
    return api("/api/findings?session=" + encodeURIComponent(sessionName)).then(function (data) {
      renderFindings(data.findings || []);
      log("[+] Findings de " + sessionName + ": " + (data.findings || []).length + " (tal cual vienen de findings_db.json).");
    }).catch(function (err) {
      renderFindings([]);
      log("[*] Sin findings para " + sessionName + ": " + err.message);
    });
  }

  function renderPlan(plan) {
    state.plan = plan;
    var steps = document.getElementById("pipelineSteps");
    steps.innerHTML = "";
    var actions = plan.actions || [];
    actions.forEach(function (action, i) {
      var li = document.createElement("li");
      li.textContent = "step" + (i + 1) + " " + action + " → Pendiente (dry-run aprobado)";
      steps.appendChild(li);
    });
    document.getElementById("planNote").textContent =
      "Plan aprobado por dry-run: " + actions.join(" → ") +
      " | Pipeline: " + plan.pipeline_profile + " | Target: " + plan.target +
      " | Scope: " + plan.scope + ". Comando exacto en la consola; confirma para ejecutar.";
    document.getElementById("mapHeader").textContent =
      "Plan aprobado (dry-run) | Target: " + plan.target + " | Sin ejecutar todavía";
  }

  function renderTasks(sessionDir, target, statusText, note) {
    var tbody = document.getElementById("tasksBody");
    tbody.innerHTML = "";
    var tr = document.createElement("tr");
    [sessionDir || "—", target || "—", statusText, "—", "—", "—", note || ""].forEach(function (v) {
      var td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }

  function phaseActions() {
    return PHASE_ACTIONS[state.phase] || [state.phase];
  }

  function startScan() {
    if (state.running) { log("[*] Ya hay una ejecución en curso."); return; }
    if (!state.connected || !state.pentestxPresent) {
      log("[!!] Sin backend: arranca python3 web-ui/server.py y recarga. No se simula nada.");
      return;
    }
    var payload = {
      target: state.config.target,
      scope: state.config.scope,
      actions: phaseActions(),
      pipeline_profile: state.config.pipeline_profile
    };
    log("[*] Dry-run: " + payload.actions.join(" ") + " sobre " + payload.target +
        " (scope " + payload.scope + ", pipeline " + payload.pipeline_profile + ")…");
    api("/api/plan", { method: "POST", body: payload }, 130000).then(function (plan) {
      if (plan.exit_code !== 0 && !plan.needs_authorization) {
        log("[!!] Dry-run rechazado por la CLI (exit " + plan.exit_code + "). No se ejecuta nada.");
        logLines(plan.stdout);
        logLines(plan.stderr);
        return;
      }
      renderPlan({
        target: payload.target, scope: payload.scope,
        actions: payload.actions, pipeline_profile: payload.pipeline_profile,
        command: plan.command, command_exact: plan.command_exact
      });
      if (plan.needs_authorization) {
        log("[!] " + (plan.authorization_note || "sin autorización confirmada") +
            ": la CLI exige una referencia en scope.yaml incluso para el " +
            "dry-run. El plan es una medición del scope; para ejecutar, " +
            "pon la referencia en scope.yaml (copia scope.example.yaml) " +
            "y marca la casilla en el diálogo de confirmación.");
      } else {
        log("[+] Dry-run OK. Comando exacto:");
      }
      log("    " + plan.command);
      if (plan.manifest) {
        log("[+] Manifiesto del dry-run: " + JSON.stringify(plan.manifest).slice(0, 500));
      }
      document.getElementById("confirmCommand").textContent = plan.command;
      document.getElementById("confirmAuth").checked = false;
      document.getElementById("confirmDialog").showModal();
    }).catch(function (err) {
      log("[!!] Dry-run rechazado: " + err.message + ". No se ejecuta nada.");
    });
  }

  function doExecute() {
    if (state.running) return;
    state.running = true;
    renderBackend();
    log("[+] Ejecutando el comando exacto del dry-run… (Pause para detener)");
    api("/api/execute", {
      method: "POST",
      body: { confirm: true,
              confirm_written_authorization:
                document.getElementById("confirmAuth").checked }
    }, 620000).then(function (res) {
      state.running = false;
      renderBackend();
      if (res.dry_run_approved === false) {
        log("[!!] No se ejecutó nada: " + (res.error || "dry-run rechazado"));
        logLines(res.stdout);
        logLines(res.stderr);
        return;
      }
      logLines(res.stdout);
      logLines(res.stderr);
      log("[+] Ejecución terminada: exit " + res.exit_code +
          (res.session_dir ? (" | sesión " + res.session_dir) : " | sin sesión nueva"));
      if (res.session_dir) {
        state.sessionDir = res.session_dir;
        document.getElementById("statusSession").textContent = "Session: " + res.session_dir;
        document.getElementById("mapHeader").textContent =
          "Session: " + res.session_dir + " | Target: " + state.config.target;
        renderTasks(res.session_dir, state.config.target,
          res.exit_code === 0 ? "Completed" : "Failed",
          "Ver manifiesto y findings en el Inspector.");
        loadFindings(res.session_dir);
      } else {
        renderTasks(null, state.config.target, "Failed", "La CLI no creó sesión.");
      }
    }).catch(function (err) {
      state.running = false;
      renderBackend();
      log("[!!] Ejecución fallida o detenida: " + err.message);
    });
  }

  function pauseScan() {
    if (!state.running) { log("[*] No hay ejecución en curso; nada que pausar."); return; }
    api("/api/stop", { method: "POST", body: {} }, 15000).then(function (res) {
      log(res.stopped ? "[*] Proceso detenido (Pause)." : "[*] No había proceso que detener.");
    }).catch(function (err) {
      log("[!!] No se pudo detener el proceso: " + err.message);
    });
  }

  /* -- Moodle SQLi (local, web-ui/tools/moodle_sqli.py) ------------- */
  /* The sesskey and cookie live only in state.moodleRequest (memory);
     they are never saved to localStorage and never logged. */

  function fillMoodleForm() {
    document.getElementById("moodleBaseUrl").value = "http://127.0.0.1:8080/moodle";
    document.getElementById("moodleSesskey").value = "";
    document.getElementById("moodleCookie").value = "";
    document.getElementById("moodleExtractDb").checked = true;
    document.getElementById("moodleExtractUser").checked = true;
    document.getElementById("moodleAuth").checked = false;
  }

  function moodleDryRun() {
    var req = state.moodleRequest;
    if (!req) return;
    log("[*] Moodle SQLi dry-run: " + req.extract.join(", ") + " en " +
        req.base_url + " (sin enviar nada)…");
    api("/api/tools/moodle-sqli/dry-run", {
      method: "POST", body: req
    }, 60000).then(function (data) {
      if (data.exit_code !== 0) {
        log("[!!] Dry-run Moodle rechazado (exit " + data.exit_code + "). No se ejecuta nada.");
        logLines(data.stderr);
        return;
      }
      log("[+] Dry-run Moodle OK. Payloads exactos (sesskey y cookie redactados):");
      (data.payloads || []).forEach(function (p) {
        log("    " + p.description);
        log("    " + p.method + " " + p.url);
        log("    body: " + JSON.stringify(p.body));
      });
      document.getElementById("moodleConfirmPayloads").textContent =
        JSON.stringify(data.payloads || [], null, 2).slice(0, 4000);
      document.getElementById("moodleConfirmAuth").checked = false;
      document.getElementById("moodleConfirmDialog").showModal();
    }).catch(function (err) {
      log("[!!] Dry-run Moodle rechazado: " + err.message + ". No se ejecuta nada.");
    });
  }

  function runMoodle() {
    var req = state.moodleRequest;
    if (!req || state.running) return;
    state.running = true;
    renderBackend();
    log("[+] Ejecutando la sonda Moodle SQLi… (lenta: segundos por carácter acertado; Pause para detener)");
    api("/api/tools/moodle-sqli/run", {
      method: "POST",
      body: { confirm: true,
              confirm_written_authorization:
                document.getElementById("moodleConfirmAuth").checked }
    }, 620000).then(function (res) {
      state.running = false;
      renderBackend();
      if (res.dry_run_approved === false) {
        log("[!!] No se ejecutó nada: " + (res.error || "dry-run rechazado"));
        logLines(res.stderr);
        return;
      }
      logLines(res.stderr);
      var result = res.result || {};
      if (result.error) log("[!!] Moodle SQLi: " + result.error);
      log("[+] Moodle SQLi terminado: exit " + res.exit_code +
          " | vulnerable: " + (result.vulnerable ? "sí" : "no") +
          " | peticiones: " + (result.requests_sent || 0));
      if (result.results) {
        Object.keys(result.results).forEach(function (k) {
          log("    " + k + ": " + result.results[k]);
        });
      }
      if (result.evidence_dir) log("[+] Evidencia: " + result.evidence_dir);
    }).catch(function (err) {
      state.running = false;
      renderBackend();
      log("[!!] Moodle SQLi fallido o detenido: " + err.message);
    });
  }

  /* -- Metasploit (local, web-ui/msf/msf_client.py) --------------- */
  /* El token Bearer de msfmcpd vive solo en el campo del diálogo
     (memoria); nunca se guarda en localStorage ni en disco. La
     lectura (buscar módulos, sesiones) no necesita casilla; check,
     run y detener sesiones exigen la casilla de autorización. Un
     payload reverse arranca antes su handler exploit/multi/handler
     por la misma conexión MCP; la sesión entrante se vincula a la
     ejecución y aparece en la tabla de sesiones. */

  function msfToken() {
    var value = document.getElementById("msfToken").value;
    return value ? value : null;
  }

  function msfRefreshStatus() {
    return api("/api/msf/status", {
      method: "POST", body: { mcp_token: msfToken() }
    }, 10000).then(function (data) {
      state.msfConnected = !!data.connected;
      state.msfDangerous = data.dangerous_actions;
      var line = document.getElementById("msfStatusLine");
      if (!data.connected) {
        line.textContent = "Metasploit no conectado — arranca msfmcpd / msfrpcd en 127.0.0.1. " + (data.error || "");
        log("[!!] Metasploit no conectado: " + (data.error || ""));
      } else {
        line.textContent = "Metasploit conectado (" + (data.url || "") + ") — acciones peligrosas: " +
          (data.dangerous_actions === true ? "ACTIVADAS" :
           data.dangerous_actions === false ? "desactivadas (arranca msfmcpd con --enable-dangerous-actions para ejecutar)" : "desconocido") +
          ((data.handlers || []).length ? " — handlers activos: " + data.handlers.length : "");
        log("[+] Metasploit conectado — acciones peligrosas: " +
          (data.dangerous_actions === true ? "activadas" : "desactivadas"));
      }
      document.getElementById("msfSearchBtn").disabled = !data.connected;
      document.getElementById("msfRefreshSessionsBtn").disabled = !data.connected;
      return data;
    }).catch(function (err) {
      state.msfConnected = false;
      document.getElementById("msfStatusLine").textContent =
        "Metasploit no conectado — " + err.message;
      log("[!!] Estado de Metasploit: " + err.message);
      return null;
    });
  }

  function msfOpen() {
    document.getElementById("msfToken").value = "";
    // Objetivo fijado: el target de Config, el mismo que usan
    // Start, el motor y Moodle. Sin Config guardada, el valor
    // por defecto de state.config (contaia.site).
    document.getElementById("msfTarget").value = state.config.target;
    document.getElementById("msfFindingsText").value = "";
    document.getElementById("msfCorrelate").innerHTML = "";
    msfLoadFindingsSessions();
    document.getElementById("msfQuery").value = "";
    document.getElementById("msfResults").innerHTML = "<li>Sin búsqueda todavía.</li>";
    document.getElementById("msfDetail").hidden = true;
    document.getElementById("msfSessions").innerHTML = "<li>Sin sesiones — actualiza la lista.</li>";
    state.msfSelected = null;
    state.msfPlan = null;
    document.getElementById("msfDialog").showModal();
    msfRefreshStatus().then(function () { msfLoadSessions(); });
  }

  function msfLoadFindingsSessions() {
    var sel = document.getElementById("msfFindingsSession");
    api("/api/sessions").then(function (data) {
      sel.innerHTML = "<option value=\"\">— elige una sesión —</option>";
      (data.sessions || []).forEach(function (s) {
        if (!s.findings) return;
        var opt = document.createElement("option");
        opt.value = s.name;
        opt.textContent = s.name;
        sel.appendChild(opt);
      });
    }).catch(function (err) {
      log("[!!] No se pudieron cargar las sesiones: " + err.message);
    });
  }

  /* Correlación findings → módulos (solo lectura del MCP). */
  function msfCorrelate() {
    var target = document.getElementById("msfTarget").value.trim() ||
      state.config.target;
    var pasted = document.getElementById("msfFindingsText").value.trim();
    var session = document.getElementById("msfFindingsSession").value;
    function run(findings) {
      log("[*] Correlacionando " + findings.length + " findings con Metasploit (solo lectura)…");
      api("/api/msf/correlate", {
        method: "POST",
        body: { target: target, findings: findings, mcp_token: msfToken() }
      }, 60000).then(function (data) {
        msfRenderCorrelations(data.correlations || [],
          document.getElementById("msfCorrelate"));
        if (data.connected === false) {
          log("[!!] " + (data.error || "Metasploit no conectado"));
        } else {
          var total = 0;
          (data.correlations || []).forEach(function (c) {
            total += (c.modules || []).length;
          });
          log("[+] Correlación: " + total + " módulos candidatos para " +
            (data.correlations || []).length + " findings.");
        }
      }).catch(function (err) {
        log("[!!] Correlación fallida: " + err.message);
      });
    }
    if (pasted) {
      try {
        var parsed = JSON.parse(pasted);
        run(Array.isArray(parsed) ? parsed : (parsed.findings || []));
      } catch (e) {
        log("[!!] Los findings pegados no son JSON válido.");
      }
      return;
    }
    if (!session) {
      log("[!!] Elige una sesión con findings o pega findings en JSON.");
      return;
    }
    api("/api/findings?session=" + encodeURIComponent(session))
      .then(function (f) { run(f.findings || []); })
      .catch(function (err) {
        log("[!!] No se pudieron leer los findings: " + err.message);
      });
  }

  function msfRenderCorrelations(correlations, box) {
    box.innerHTML = "";
    if (!correlations.length) {
      box.innerHTML = "<p class=\"muted\">Sin findings para correlacionar.</p>";
      return;
    }
    var total = 0;
    correlations.forEach(function (c) { total += (c.modules || []).length; });
    if (!total) {
      box.innerHTML = "<p class=\"muted\">Sin módulos candidatos para estos findings (Metasploit conectado, pero nada coincide).</p>";
      return;
    }
    correlations.forEach(function (entry) {
      var f = entry.finding || {};
      var h = document.createElement("h4");
      h.textContent = (f.id || f.title || "finding") +
        (f.cve ? " — " + f.cve : "") +
        (f.service ? " (" + f.service + (f.port ? ":" + f.port : "") + ")" : "");
      box.appendChild(h);
      var ul = document.createElement("ul");
      ul.className = "msf-results";
      (entry.modules || []).forEach(function (m) {
        var li = document.createElement("li");
        var btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = m.type + "/" + m.name +
          " — rango " + m.rank + " (" + m.reason + ") — Usar";
        btn.addEventListener("click", function () {
          msfUseCandidate(m.type, m.name);
        });
        li.appendChild(btn);
        ul.appendChild(li);
      });
      box.appendChild(ul);
    });
  }

  function msfUseCandidate(type, name) {
    // Carga el módulo y sus opciones en el diálogo MSF con el
    // target ya fijado (msfTarget): msfRenderOptions lo usa como
    // RHOSTS cuando el módulo no trae default.
    log("[*] Módulo correlacionado cargado: " + type + "/" + name +
      " (target fijado: " +
      (document.getElementById("msfTarget").value.trim() ||
        state.config.target) + ").");
    msfSelectModule(type, name);
  }

  function msfSearch() {
    if (!state.msfConnected) {
      log("[!!] Metasploit no conectado: busca después de arrancar msfmcpd.");
      return;
    }
    var query = document.getElementById("msfQuery").value.trim();
    var type = document.getElementById("msfType").value;
    if (!query && !type) {
      log("[!!] Escribe un término de búsqueda o elige un tipo de módulo.");
      return;
    }
    log("[*] Buscando módulos Metasploit: " + (query || type) + "…");
    api("/api/msf/search", {
      method: "POST",
      body: { query: query || type, limit: 100, mcp_token: msfToken() }
    }, 30000).then(function (data) {
      var modules = data.modules || [];
      if (type) modules = modules.filter(function (m) { return m.type === type; });
      var list = document.getElementById("msfResults");
      if (!modules.length) {
        list.innerHTML = "<li>Sin módulos para esa búsqueda.</li>";
        log("[*] Sin módulos para esa búsqueda.");
        return;
      }
      list.innerHTML = "";
      modules.forEach(function (m) {
        var li = document.createElement("li");
        var btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = m.type + "/" + m.name +
          (m.description ? " — " + m.description : "");
        btn.addEventListener("click", function () {
          msfSelectModule(m.type, m.name);
        });
        li.appendChild(btn);
        list.appendChild(li);
      });
      log("[+] " + modules.length + " módulos encontrados.");
    }).catch(function (err) {
      log("[!!] Búsqueda Metasploit fallida: " + err.message);
    });
  }

  function msfSelectModule(type, name) {
    log("[*] Módulo seleccionado: " + type + "/" + name);
    api("/api/msf/module-info", {
      method: "POST",
      body: { type: type, name: name, mcp_token: msfToken() }
    }, 30000).then(function (data) {
      var info = data.data || {};
      state.msfSelected = { type: type, name: name, info: info };
      document.getElementById("msfDetailTitle").textContent = type + "/" + name;
      document.getElementById("msfDetailDesc").textContent = info.description || "";
      msfRenderOptions(info.options || []);
      document.getElementById("msfDetail").hidden = false;
      document.getElementById("msfReverseNote").hidden = true;
    }).catch(function (err) {
      log("[!!] No se pudo cargar el módulo: " + err.message);
    });
  }

  function msfRenderOptions(options) {
    var box = document.getElementById("msfOptions");
    box.innerHTML = "";
    var list = Array.isArray(options) ? options : Object.keys(options || {}).map(function (k) {
      var opt = options[k] || {};
      return { name: k, required: !!opt.required, default: opt.default, description: opt.description || "" };
    });
    list.forEach(function (opt) {
      var label = document.createElement("label");
      label.textContent = opt.name + (opt.required ? " (obligatorio)" : "") +
        (opt.description ? " — " + opt.description : "");
      var input = document.createElement("input");
      input.type = "text";
      input.setAttribute("data-msf-option", opt.name);
      var value = opt.default;
      // RHOSTS pre-rellenado con el objetivo fijado (el campo
      // Target del diálogo MSF, que viene de Config); LHOST solo
      // 127.0.0.1. Sin Config guardada, state.config trae el
      // valor por defecto (contaia.site).
      if (opt.name === "RHOSTS" && (value === "" || value === undefined || value === null)) {
        var fixed = document.getElementById("msfTarget").value.trim();
        value = fixed || state.config.target;
      }
      if (opt.name === "LHOST" && (value === "" || value === undefined || value === null)) value = "127.0.0.1";
      if (value !== undefined && value !== null) input.value = String(value);
      label.appendChild(input);
      box.appendChild(label);
    });
    if (!list.length) {
      box.innerHTML = "<p class=\"muted\">Este módulo no declara opciones.</p>";
    }
  }

  function msfCollectOptions() {
    var options = {};
    document.querySelectorAll("[data-msf-option]").forEach(function (input) {
      var value = input.value.trim();
      if (value !== "") options[input.getAttribute("data-msf-option")] = value;
    });
    return options;
  }

  function msfPlan(action) {
    if (!state.msfSelected) {
      log("[!!] Elige primero un módulo de la lista.");
      return;
    }
    var options = msfCollectOptions();
    // Si el módulo no declara RHOSTS, el objetivo fijado manda:
    // el target de Config que lleva el diálogo MSF.
    if (!options.RHOSTS && !options.RHOST) {
      var fixedTarget = document.getElementById("msfTarget").value.trim() ||
        state.config.target;
      options.RHOSTS = fixedTarget;
    }
    var payload = (options.PAYLOAD || "");
    var reverse = payload.toLowerCase().indexOf("reverse") !== -1;
    document.getElementById("msfReverseNote").hidden = !reverse;
    log("[*] Plan Metasploit (" + action + "): " +
      state.msfSelected.type + "/" + state.msfSelected.name +
      (reverse ? " — payload reverse: se arrancará el handler multi/handler antes." : ""));
    api("/api/msf/plan", {
      method: "POST",
      body: { type: state.msfSelected.type, name: state.msfSelected.name,
              action: action, options: options, mcp_token: msfToken() }
    }, 30000).then(function (data) {
      state.msfPlan = data.plan;
      state.msfAction = action;
      state.msfPendingStop = null;
      logLines(data.summary);
      if (data.plan.reverse) {
        log("[+] Payload reverse: el handler exploit/multi/handler se arrancará antes del exploit, por la misma conexión MCP.");
      }
      document.getElementById("msfConfirmText").textContent = data.summary;
      document.getElementById("msfConfirmAuth").checked = false;
      document.getElementById("msfConfirmDialog").showModal();
    }).catch(function (err) {
      log("[!!] Plan Metasploit rechazado: " + err.message + ". No se ejecuta nada.");
    });
  }

  function msfExecute() {
    if (state.msfPendingStop !== null) {
      var sessionId = state.msfPendingStop;
      state.msfPendingStop = null;
      log("[+] Deteniendo sesión Metasploit " + sessionId + "…");
      api("/api/msf/session/stop", {
        method: "POST",
        body: { confirm: true,
                confirm_written_authorization:
                  document.getElementById("msfConfirmAuth").checked,
                session_id: sessionId, mcp_token: msfToken() }
      }, 30000).then(function (res) {
        log("[+] Sesión " + sessionId + " detenida. Evidencia: " + (res.evidence_dir || ""));
        msfLoadSessions();
      }).catch(function (err) {
        log("[!!] No se pudo detener la sesión: " + err.message);
      });
      return;
    }
    var action = state.msfAction;
    if (!action || !state.msfPlan) {
      log("[!!] Sin plan Metasploit aprobado.");
      return;
    }
    state.running = true;
    renderBackend();
    log("[+] Ejecutando módulo Metasploit (" + action + "): " +
      state.msfPlan.type + "/" + state.msfPlan.name + "…");
    api("/api/msf/" + action, {
      method: "POST",
      body: { confirm: true,
              confirm_written_authorization:
                document.getElementById("msfConfirmAuth").checked,
              mcp_token: msfToken() }
    }, 180000).then(function (res) {
      state.running = false;
      renderBackend();
      log("[+] Metasploit (" + action + ") terminado: " + res.status +
        " | run " + res.run_id);
      if (res.handler) {
        log("    handler: " + res.handler.name + " uuid " + (res.handler.uuid || "") +
          " LHOST " + res.handler.LHOST + " LPORT " + res.handler.LPORT +
          (res.handler.reused ? " (reutilizado)" : ""));
      }
      if (res.handler_error) log("[!!] El handler falló: " + res.handler_error);
      if (res.result) logLines(JSON.stringify(res.result, null, 2));
      if (res.sessions_linked && res.sessions_linked.length) {
        log("[+] Sesiones vinculadas a esta ejecución: " + res.sessions_linked.join(", "));
      }
      if (res.evidence_dir) log("[+] Evidencia: " + res.evidence_dir);
      msfLoadSessions();
    }).catch(function (err) {
      state.running = false;
      renderBackend();
      log("[!!] Metasploit fallido o detenido: " + err.message);
    });
  }

  function msfLoadSessions() {
    if (!state.msfConnected) return;
    api("/api/msf/sessions", null, 15000).then(function (data) {
      var sessions = data.sessions || {};
      var list = document.getElementById("msfSessions");
      var ids = Object.keys(sessions);
      if (!ids.length) {
        list.innerHTML = "<li>Sin sesiones activas.</li>";
        return;
      }
      list.innerHTML = "";
      ids.forEach(function (id) {
        var s = sessions[id] || {};
        var li = document.createElement("li");
        var text = document.createElement("span");
        text.textContent = "#" + id + " " + (s.type || "") +
          " — " + (s.target_host || s.tunnel_peer || "") +
          (s.via_exploit ? " — vía " + s.via_exploit : "") +
          (s.via_payload ? " (" + s.via_payload + ")" : "");
        var btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = "Detener";
        btn.addEventListener("click", function () {
          state.msfPendingStop = parseInt(id, 10);
          document.getElementById("msfConfirmText").textContent =
            "Detener la sesión Metasploit #" + id + " (" + (s.type || "") +
            (s.via_exploit ? ", vía " + s.via_exploit : "") + ").";
          document.getElementById("msfConfirmAuth").checked = false;
          document.getElementById("msfConfirmDialog").showModal();
        });
        li.appendChild(text);
        li.appendChild(document.createTextNode(" "));
        li.appendChild(btn);
        list.appendChild(li);
      });
    }).catch(function (err) {
      log("[!!] No se pudieron cargar las sesiones: " + err.message);
    });
  }

  /* -- Planning engine (web-ui/engine/engine.py) ----------------- */
  /* The Moodle sesskey/cookie live only in the dialog fields and in
     the plan request (memory); they are never saved to localStorage. */

  /* Cada goal fija su scope: msf_targeted ejecuta módulos y
     exige scope active, como full_assessment. */
  var ENGINE_GOAL_SCOPES = {
    owasp_report: "passive",
    full_assessment: "active",
    moodle_sqli_confirm: "passive",
    msf_targeted: "active"
  };

  function syncEngineScope() {
    var goal = document.getElementById("engineGoal").value;
    document.getElementById("engineScope").value =
      ENGINE_GOAL_SCOPES[goal] || state.config.scope;
  }

  function fillEngineForm() {
    document.getElementById("engineGoal").value = "owasp_report";
    document.getElementById("engineTarget").value = state.config.target;
    syncEngineScope();
    document.getElementById("engineAuth").checked = false;
    document.getElementById("engineMoodleBaseUrl").value = "http://127.0.0.1:8080/moodle";
    document.getElementById("engineMoodleSesskey").value = "";
    document.getElementById("engineMoodleCookie").value = "";
    toggleEngineMoodleFields();
  }

  function toggleEngineMoodleFields() {
    document.getElementById("engineMoodleFields").hidden =
      document.getElementById("engineGoal").value !== "moodle_sqli_confirm";
  }

  function renderEnginePlan(plan) {
    state.enginePlan = plan;
    var steps = document.getElementById("pipelineSteps");
    steps.innerHTML = "";
    (plan.steps || []).forEach(function (step, i) {
      var li = document.createElement("li");
      li.textContent = "step" + (i + 1) + " " + step.id + " (" + step.tool + ") → " + step.status +
        (step.blocked_reason ? " (" + step.blocked_reason + ")" : "");
      steps.appendChild(li);
    });
    document.getElementById("planNote").textContent =
      "Plan del motor: goal " + plan.goal + " | Target: " + plan.target +
      " | Scope: " + plan.scope + " | Pipeline: " + plan.pipeline_profile +
      " | " + (plan.authorization_note || "sin autorización confirmada") +
      (plan.msf_findings ? " | Findings del mapeo: " + plan.msf_findings.length : "") +
      (plan.warnings && plan.warnings.length ? " | Avisos: " + plan.warnings.join("; ") : "") +
      ". Confirma para ejecutar paso a paso.";
    document.getElementById("correlateResults").innerHTML = "";
    document.getElementById("mapHeader").textContent =
      "Plan del motor aprobado | Goal: " + plan.goal + " | Sin ejecutar todavía";
    showTab("plan");
  }

  function enginePlan() {
    if (!state.connected) {
      log("[!!] Sin backend: arranca python3 web-ui/server.py y recarga. El motor no simula nada.");
      return;
    }
    var goal = document.getElementById("engineGoal").value;
    var body = {
      goal: goal,
      target: document.getElementById("engineTarget").value.trim(),
      scope: document.getElementById("engineScope").value,
      confirm_written_authorization:
        document.getElementById("engineAuth").checked
    };
    if (goal === "moodle_sqli_confirm") {
      body.moodle = {
        base_url: document.getElementById("engineMoodleBaseUrl").value.trim(),
        sesskey: document.getElementById("engineMoodleSesskey").value.trim(),
        session_cookie: document.getElementById("engineMoodleCookie").value.trim()
      };
    }
    log("[*] Motor: generando plan (" + goal + " sobre " + body.target + ")…");
    api("/api/engine/plan", { method: "POST", body: body }, 30000).then(function (data) {
      renderEnginePlan(data.plan);
      log("[+] Plan del motor generado: " + data.plan.steps.length + " pasos.");
      (data.plan.warnings || []).forEach(function (w) { log("[!] " + w); });
      document.getElementById("engineConfirmPlan").textContent =
        JSON.stringify(data.plan.steps.map(function (step) {
          return { id: step.id, action: step.action, tool: step.tool,
            status: step.status, dry_run_command: step.dry_run_command };
        }), null, 2).slice(0, 4000);
      document.getElementById("engineConfirmAuth").checked = false;
      document.getElementById("engineConfirmDialog").showModal();
    }).catch(function (err) {
      log("[!!] Plan del motor rechazado: " + err.message + ". No se ejecuta nada.");
    });
  }

  function engineRun() {
    if (state.running || !state.enginePlan) return;
    state.running = true;
    renderBackend();
    log("[+] Ejecutando el plan del motor paso a paso… (Pause para detener)");
    api("/api/engine/run", {
      method: "POST",
      body: { confirm: true,
              confirm_written_authorization:
                document.getElementById("engineConfirmAuth").checked }
    }, 1800000).then(function (res) {
      state.running = false;
      renderBackend();
      log("[+] Plan terminado: " + res.status + " | run " + res.run_id);
      (res.steps || []).forEach(function (step) {
        log("    " + step.id + " → " + step.status +
          (step.reason ? " (" + step.reason + ")" : "") +
          (step.session_dir ? " | sesión " + step.session_dir : ""));
        if (step.stdout) logLines(step.stdout);
        if (step.stderr) logLines(step.stderr);
        if (step.module) {
          log("    módulo: " + step.module +
            (step.sessions_linked && step.sessions_linked.length ?
              " | sesiones vinculadas: " + step.sessions_linked.join(", ") : ""));
        }
        if (step.result && step.result.results) {
          Object.keys(step.result.results).forEach(function (k) {
            log("    " + k + ": " + step.result.results[k]);
          });
        }
      });
      // La correlación findings → módulos del goal msf_targeted
      // se muestra en Plan Overview, con botón "Usar" por módulo.
      var correlations = [];
      (res.steps || []).forEach(function (step) {
        if (step.correlations) {
          correlations = correlations.concat(step.correlations);
        }
      });
      if (correlations.length) {
        msfRenderCorrelations(
          correlations, document.getElementById("correlateResults"));
        log("[+] Correlación MSF en Plan Overview: " +
          correlations.length + " findings con candidatos.");
      }
      if (res.evidence_dir) log("[+] Evidencia: " + res.evidence_dir);
      var last = (res.steps || []).filter(function (step) { return step.session_dir; }).pop();
      if (last) {
        state.sessionDir = last.session_dir;
        loadFindings(last.session_dir);
      }
      loadSessions();
    }).catch(function (err) {
      state.running = false;
      renderBackend();
      log("[!!] Plan fallido o detenido: " + err.message);
    });
  }

  function resetSession() {
    state.plan = null;
    state.sessionDir = null;
    state.config = {
      target: "contaia.site", scope: "passive",
      pipeline_profile: "with_owasp"
    };
    saveConfig();
    fillConfigForm();
    document.getElementById("pipelineSteps").innerHTML =
      "<li>Sin plan — pulsa Start para generar un dry-run.</li>";
    document.getElementById("planNote").textContent =
      "Sin plan — el plan real aparece aquí tras el dry-run.";
    document.getElementById("mapHeader").textContent =
      "Sin sesión | Map View • Sin hosts • Arranca el backend y pulsa Start";
    document.getElementById("statusSession").textContent = "Session: — | Sin sesión";
    renderTasks(null, null, "—", "Sin sesión — no hay tareas todavía.");
    renderFindings([]);
    log("[+] Configuración restablecida a los valores por defecto (contaia.site, passive, with_owasp).");
  }

  function download(filename, text, type) {
    var blob = new Blob([text], { type: type || "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  function exportReport() {
    if (!state.connected) { log("[!!] Sin backend: no hay nada real que exportar."); return; }
    api("/api/sessions").then(function (data) {
      var sessions = data.sessions || [];
      if (!sessions.length) { log("[*] No hay sesiones reales todavía; nada que exportar."); return; }
      var latest = sessions[0];
      return api("/api/findings?session=" + encodeURIComponent(latest.name)).then(function (f) {
        return { session: latest, findings: f.findings || [] };
      }).catch(function () {
        return { session: latest, findings: [] };
      });
    }).then(function (result) {
      if (!result) return;
      var report = {
        session: result.session.name,
        manifest: result.session.manifest,
        target: state.config.target,
        scope: state.config.scope,
        pipeline_profile: state.config.pipeline_profile,
        plan_command: state.plan ? state.plan.command : null,
        findings: result.findings
      };
      download("pent3stx-" + result.session.name + "-report.json", JSON.stringify(report, null, 2));
      log("[+] Reporte real exportado: sesión " + result.session.name + ", " + result.findings.length + " findings.");
    }).catch(function (err) {
      log("[!!] Export fallido: " + err.message);
    });
  }

  function saveConfig() {
    try {
      localStorage.setItem("pent3stx-config", JSON.stringify(state.config));
      log("[+] Configuración guardada en este navegador (target, scope, pipeline).");
    } catch (e) {
      log("[!!] No se pudo guardar la configuración: " + e.message);
    }
  }

  function syncQuickConfigFromState() {
    document.getElementById("quickTarget").value = state.config.target;
    document.getElementById("quickScope").value = state.config.scope;
    document.getElementById("quickPipeline").value = state.config.pipeline_profile;
  }

  function applyQuickConfig() {
    state.config.target = document.getElementById("quickTarget").value.trim();
    state.config.scope = document.getElementById("quickScope").value;
    state.config.pipeline_profile = document.getElementById("quickPipeline").value;
    saveConfig();
    log("[*] Configuración aplicada: " + state.config.target + ", " +
        state.config.scope + ", " + state.config.pipeline_profile + ".");
  }

  function loadSavedConfig() {
    try {
      var raw = localStorage.getItem("pent3stx-config");
      if (!raw) return;
      var c = JSON.parse(raw);
      if (typeof c.target === "string" && c.target) state.config.target = c.target;
      if (c.scope === "passive" || c.scope === "active") state.config.scope = c.scope;
      if (typeof c.pipeline_profile === "string") state.config.pipeline_profile = c.pipeline_profile;
      // Una referencia guardada por una versión anterior se ignora:
      // la referencia ya no vive en Config ni en localStorage.
      log("[*] Configuración restaurada de este navegador.");
    } catch (e) { /* keep defaults */ }
  }

  function fillConfigForm() {
    document.getElementById("cfgTarget").value = state.config.target;
    document.getElementById("cfgScope").value = state.config.scope;
    document.getElementById("cfgPipeline").value = state.config.pipeline_profile;
    syncQuickConfigFromState();
  }

  function selectPhase(phase) {
    state.phase = phase;
    document.querySelectorAll(".phase").forEach(function (el) {
      el.classList.toggle("selected", el.getAttribute("data-phase") === phase);
    });
    document.getElementById("planNote").textContent =
      "Fase seleccionada: " + phase + " (acciones: " + phaseActions().join(", ") + "). " +
      "Pulsa Start para el dry-run real con esa fase.";
    log("[*] Fase seleccionada: " + phase + ".");
  }

  function openFilePicker(mode) {
    fileInput.value = "";
    fileInput.onchange = function () {
      var f = fileInput.files && fileInput.files[0];
      if (!f) return;
      var reader = new FileReader();
      reader.onload = function () {
        var text = String(reader.result || "");
        if (text.length > 1024 * 1024) {
          log("[!!] " + mode + ": archivo demasiado grande (más de 1 MiB): " + f.name);
          return;
        }
        log("[+] " + mode + ": archivo local cargado solo como datos (no ejecutado): " + f.name +
            " (" + f.size + " bytes, " + text.split(/\n/).length + " líneas).");
      };
      reader.readAsText(f);
    };
    fileInput.click();
  }

  function showTab(which) {
    document.querySelectorAll(".center-tab").forEach(function (t) {
      var active = t.getAttribute("data-center-tab") === which;
      t.classList.toggle("active", active);
      t.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.getElementById("mapView").hidden = which !== "map";
    document.getElementById("planView").hidden = which !== "plan";
    log("[*] Vista central: " + (which === "map" ? "Session Map" : "Plan Overview") + ".");
  }

  function showInspector(which) {
    document.querySelectorAll(".insp-tab").forEach(function (t) {
      var active = t.getAttribute("data-insp-tab") === which;
      t.classList.toggle("active", active);
      t.setAttribute("aria-selected", active ? "true" : "false");
    });
    ["pipeline", "profiles", "findings"].forEach(function (name) {
      document.getElementById("pane-" + name).hidden = name !== which;
    });
  }

  var actions = {
    "new": resetSession,
    "open": function () { openFilePicker("Open"); },
    "import": function () { openFilePicker("Import"); },
    "start": startScan,
    "scan": startScan,
    "pause": pauseScan,
    "export": exportReport,
    "save": saveConfig,
    "apply-run-config": applyQuickConfig,
    "config": function () { fillConfigForm(); document.getElementById("configDialog").showModal(); },
    "about": function () { document.getElementById("aboutDialog").showModal(); },
    "authorized-note": function () {
      log("[!!] Nota: evaluación autorizada únicamente. Solo contaia.site y 127.0.0.1, con autorización escrita.");
    },
    "copy-plan": function () {
      var text = state.plan
        ? "Pent3stX — " + state.plan.command
        : "Pent3stX — sin plan todavía. Pulsa Start para el dry-run.";
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () { log("[+] Plan copiado al portapapeles."); });
      } else { log("[*] Plan: " + text); }
    },
    "clear-console": function () {
      consoleBody.textContent = stamp() + "[*] Consola limpiada.";
    },
    "toggle-console": function () {
      document.getElementById("consolePanel").classList.toggle("collapsed");
    },
    "toggle-inspector": function () {
      document.getElementById("rightPanel").classList.toggle("hidden");
    },
    "toggle-map": function () { showTab("map"); },
    "toggle-tree": function () {
      document.getElementById("phaseTree").classList.toggle("collapsed");
    },
    "analyze-ports": function () {
      if (!state.sessionDir) {
        log("[*] Sin sesión real todavía: ejecuta un plan primero para analizar puertos de sus findings.");
        return;
      }
      loadFindings(state.sessionDir);
      log("[*] Puertos: revisa los findings reales de la sesión " + state.sessionDir + " (sin escaneo nuevo).");
    },
    "engine-plan": function () {
      if (!state.connected) {
        log("[!!] Sin backend: arranca python3 web-ui/server.py y recarga. El motor no se simula.");
        return;
      }
      fillEngineForm();
      document.getElementById("engineDialog").showModal();
    },
    "moodle-sqli": function () {
      if (!state.connected) {
        log("[!!] Sin backend: arranca python3 web-ui/server.py y recarga. La sonda Moodle no se simula.");
        return;
      }
      fillMoodleForm();
      document.getElementById("moodleDialog").showModal();
    },
    "msf": function () {
      if (!state.connected) {
        log("[!!] Sin backend: arranca python3 web-ui/server.py y recarga. El panel Metasploit no se simula.");
        return;
      }
      msfOpen();
    },
    "plugins-none": function () { log("[*] Plugins: ninguno cargado."); },
    "show-plan": function () { showTab("plan"); },
    "show-findings": function () { showInspector("findings"); },
    "reset-layout": function () {
      document.getElementById("rightPanel").classList.remove("hidden");
      document.getElementById("consolePanel").classList.remove("collapsed");
      document.getElementById("phaseTree").classList.remove("collapsed");
      showTab("map"); showInspector("pipeline");
      log("[*] Layout restablecido a los valores del diseño 1.");
    }
  };

  document.querySelectorAll("[data-action]").forEach(function (el) {
    el.addEventListener("click", function (ev) {
      ev.stopPropagation();
      var name = el.getAttribute("data-action");
      closeMenus();
      if (actions[name]) actions[name]();
    });
  });

  function closeMenus() {
    document.querySelectorAll(".menu.open").forEach(function (m) { m.classList.remove("open"); });
  }
  document.querySelectorAll(".menu-btn").forEach(function (btn) {
    btn.addEventListener("click", function (ev) {
      ev.stopPropagation();
      var menu = btn.parentElement;
      var wasOpen = menu.classList.contains("open");
      closeMenus();
      if (!wasOpen) menu.classList.add("open");
    });
  });
  document.addEventListener("click", closeMenus);

  document.querySelectorAll(".phase").forEach(function (el) {
    el.addEventListener("click", function () { selectPhase(el.getAttribute("data-phase")); });
  });

  document.querySelectorAll(".center-tab").forEach(function (t) {
    t.addEventListener("click", function () { showTab(t.getAttribute("data-center-tab")); });
  });
  document.querySelectorAll(".insp-tab").forEach(function (t) {
    t.addEventListener("click", function () { showInspector(t.getAttribute("data-insp-tab")); });
  });

  document.querySelectorAll(".win-btn").forEach(function (b) {
    b.addEventListener("click", function () {
      var w = b.getAttribute("data-win");
      if (w === "min") log("[*] Minimize no está disponible para una página web; el workbench sigue abierto.");
      if (w === "max") {
        if (document.fullscreenElement) document.exitFullscreen();
        else if (document.documentElement.requestFullscreen) document.documentElement.requestFullscreen();
        log("[*] Pantalla completa alternada.");
      }
      if (w === "close") log("[*] Close está deshabilitado en esta vista; usa la pestaña del navegador para salir.");
    });
  });

  document.getElementById("optMotion").addEventListener("change", function (ev) {
    document.body.classList.toggle("reduced-motion", ev.target.checked);
    log("[*] Reduced motion " + (ev.target.checked ? "activado." : "desactivado."));
  });
  document.getElementById("optConsole").addEventListener("change", function (ev) {
    document.getElementById("consolePanel").classList.toggle("collapsed", !ev.target.checked);
  });

  document.getElementById("configForm").addEventListener("submit", function () {
    state.config.target = document.getElementById("cfgTarget").value.trim();
    state.config.scope = document.getElementById("cfgScope").value;
    state.config.pipeline_profile = document.getElementById("cfgPipeline").value;
    syncQuickConfigFromState();
    saveConfig();
    log("[*] Configuración actualizada: " + state.config.target + ", " +
        state.config.scope + ", " + state.config.pipeline_profile + ".");
  });

  // La casilla de autorización bloquea la confirmación en la UI:
  // sin marcarla, el diálogo no se cierra ni se ejecuta nada.
  function requireAuthCheckbox(formId, checkboxId) {
    document.getElementById(formId).addEventListener("submit", function (ev) {
      if (ev.submitter && ev.submitter.value === "cancel") return;
      if (!document.getElementById(checkboxId).checked) {
        ev.preventDefault();
        log("[!!] Marca la casilla 'Confirmo que tengo autorización escrita para este alcance' para ejecutar.");
      }
    });
  }
  requireAuthCheckbox("confirmForm", "confirmAuth");
  requireAuthCheckbox("engineConfirmForm", "engineConfirmAuth");
  requireAuthCheckbox("moodleConfirmForm", "moodleConfirmAuth");
  requireAuthCheckbox("msfConfirmForm", "msfConfirmAuth");

  document.getElementById("confirmDialog").addEventListener("close", function () {
    if (document.getElementById("confirmDialog").returnValue === "confirm") {
      doExecute();
    } else {
      log("[*] Ejecución cancelada por el usuario. El dry-run sigue aprobado para ese comando exacto.");
    }
  });

  document.getElementById("engineGoal").addEventListener("change", function () {
    toggleEngineMoodleFields();
    syncEngineScope();
  });

  document.getElementById("engineForm").addEventListener("submit", function (ev) {
    if (ev.submitter && ev.submitter.value === "cancel") return;
    enginePlan();
  });

  document.getElementById("engineConfirmDialog").addEventListener("close", function () {
    if (document.getElementById("engineConfirmDialog").returnValue === "confirm") {
      engineRun();
    } else {
      log("[*] Plan del motor cancelado por el usuario. El plan sigue aprobado para ese goal exacto.");
    }
  });

  document.getElementById("moodleForm").addEventListener("submit", function (ev) {
    if (ev.submitter && ev.submitter.value === "cancel") return;
    var extract = [];
    if (document.getElementById("moodleExtractDb").checked) extract.push("database");
    if (document.getElementById("moodleExtractUser").checked) extract.push("username");
    state.moodleRequest = {
      base_url: document.getElementById("moodleBaseUrl").value.trim(),
      sesskey: document.getElementById("moodleSesskey").value.trim(),
      session_cookie: document.getElementById("moodleCookie").value.trim(),
      extract: extract,
      confirm_written_authorization:
        document.getElementById("moodleAuth").checked
    };
    moodleDryRun();
  });

  document.getElementById("moodleConfirmDialog").addEventListener("close", function () {
    if (document.getElementById("moodleConfirmDialog").returnValue === "confirm") {
      runMoodle();
    } else {
      log("[*] Sonda Moodle cancelada por el usuario. El dry-run sigue aprobado para ese comando exacto.");
    }
  });

  document.getElementById("msfSearchBtn").addEventListener("click", msfSearch);
  document.getElementById("msfCorrelateBtn").addEventListener("click", msfCorrelate);
  document.getElementById("msfRefreshSessionsBtn").addEventListener("click", function () {
    msfRefreshStatus().then(function () { msfLoadSessions(); });
  });
  document.getElementById("msfCheckBtn").addEventListener("click", function () { msfPlan("check"); });
  document.getElementById("msfRunBtn").addEventListener("click", function () { msfPlan("run"); });

  document.getElementById("msfConfirmDialog").addEventListener("close", function () {
    if (document.getElementById("msfConfirmDialog").returnValue === "confirm") {
      msfExecute();
    } else {
      log("[*] Ejecución Metasploit cancelada por el usuario. El plan sigue aprobado para ese módulo exacto.");
    }
  });

  loadSavedConfig();
  fillConfigForm();
  renderBackend();
  checkBackend();
})();
