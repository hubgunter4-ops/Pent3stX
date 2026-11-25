/* Pent3stX Workbench — Design Option 1 (local simulation only).
   No network traffic: Start / Pause only advance the OWASP scan
   simulation (12/25 checks, 48%) in this page. Every control has a
   visible effect: it updates the console, the selection, a panel,
   or a status line. Nothing here runs pentestx.py or any scanner. */
(function () {
  "use strict";

  var state = {
    running: false,
    checks: 12,
    totalChecks: 25,
    phase: "owasp_web",
    timer: null,
    savedAt: null
  };

  var consoleBody = document.getElementById("consoleBody");
  var progressFill = document.getElementById("progressFill");
  var pipelinePct = document.getElementById("pipelinePct");
  var checkCount = document.getElementById("checkCount");
  var pipelineState = document.getElementById("pipelineState");
  var owaspStatus = document.getElementById("owaspStatus");
  var owaspNote = document.getElementById("owaspNote");
  var corrStatus = document.getElementById("corrStatus");
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

  function pct() {
    return Math.round((state.checks / state.totalChecks) * 100);
  }

  function render() {
    progressFill.style.width = pct() + "%";
    pipelinePct.textContent = pct();
    checkCount.textContent = state.checks;
    if (state.checks >= state.totalChecks) {
      pipelineState.textContent = "Completed (100%)";
      owaspStatus.textContent = "Completed";
      owaspStatus.className = "badge done";
      owaspNote.textContent = "Completed, 25 checks";
      corrStatus.textContent = "Running";
      corrStatus.className = "badge running";
    } else {
      pipelineState.textContent = "Running (" + pct() + "%)";
      owaspStatus.textContent = "Running";
      owaspStatus.className = "badge running";
      owaspNote.textContent = "In progress, " + state.checks + " checks";
    }
    document.querySelectorAll('[data-action="start"]').forEach(function (b) {
      b.classList.toggle("active", state.running);
    });
  }

  function advance() {
    if (!state.running || state.checks >= state.totalChecks) { stopTimer(); return; }
    state.checks += 1;
    log("[*] Running check " + state.checks + "/" + state.totalChecks + ": Header Analysis..");
    render();
    if (state.checks >= state.totalChecks) {
      state.running = false;
      log("[+] OWASP scan completed: 25/25 checks. Correlation can start.");
      log("[!!] Note: This is an authorized assessment. Do not perform actions outside approved scope.");
    }
  }

  function stopTimer() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
  }

  function startScan() {
    if (state.checks >= state.totalChecks) {
      log("[*] Scan already completed (25/25). Use New to reset the session.");
      return;
    }
    if (state.running) { log("[*] Scan already running (" + state.checks + "/25)."); return; }
    state.running = true;
    stopTimer();
    state.timer = setInterval(advance, 1500);
    log("[+] Starting OWASP scan on srv-web-01:80 (local simulation, no network traffic) ..");
    render();
  }

  function pauseScan() {
    if (!state.running) { log("[*] Scan is not running; nothing to pause."); return; }
    state.running = false;
    stopTimer();
    log("[*] Scan paused at check " + state.checks + "/25 (" + pct() + "%).");
    render();
  }

  function resetSession() {
    state.running = false;
    stopTimer();
    state.checks = 12;
    state.phase = "owasp_web";
    selectPhase("owasp_web");
    render();
    log("[+] New session initialized: SA-2024-011 (local view reset to 12/25 checks, 48%).");
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
    var report = {
      session: "SA-2024-011",
      scope: "10.10.50.0/24",
      user: "sec-analyst",
      version: "v1.2.0-design1",
      phase: state.phase,
      owasp_checks: state.checks + "/25",
      progress_pct: pct(),
      hosts: ["srv-web-01 (10.10.50.10) http:80", "srv-api-02 (10.10.50.11) api:443",
              "db-01 (10.10.50.20) postgres:5432", "fw-gateway (10.10.50.1) firewall"],
      findings_shown: [
        "[MED] Outdated Server Header — srv-web-01:80 — CWE-1008",
        "[LOW] TLS 1.0 Supported — srv-api-02:443 — CWE-326",
        "[INFO] Open DB Port Detected — db-01:5432 — Internal only"
      ],
      note: "Local simulation only. No network traffic was generated by this page."
    };
    download("pent3stx-SA-2024-011-report.json", JSON.stringify(report, null, 2));
    log("[+] Report exported: pent3stx-SA-2024-011-report.json (local download).");
  }

  function saveState() {
    try {
      localStorage.setItem("pent3stx-design1", JSON.stringify({
        checks: state.checks, phase: state.phase, savedAt: new Date().toISOString()
      }));
      state.savedAt = new Date().toISOString();
      log("[+] State saved in this browser (checks " + state.checks + "/25, phase " + state.phase + ").");
    } catch (e) {
      log("[!!] Could not save state in this browser: " + e.message);
    }
  }

  function loadSavedState() {
    try {
      var raw = localStorage.getItem("pent3stx-design1");
      if (!raw) return;
      var s = JSON.parse(raw);
      if (typeof s.checks === "number" && s.checks >= 0 && s.checks <= 25) {
        state.checks = s.checks;
        if (s.phase) selectPhase(s.phase);
        log("[*] Restored saved state from this browser (checks " + s.checks + "/25).");
      }
    } catch (e) { /* keep the design defaults */ }
  }

  function selectPhase(phase) {
    state.phase = phase;
    document.querySelectorAll(".phase").forEach(function (el) {
      el.classList.toggle("selected", el.getAttribute("data-phase") === phase);
    });
    var label = phase.replace(/-/g, " ");
    document.getElementById("planView").querySelector(".plan-note").textContent =
      "Selected phase: " + label + ". Plan: passive → active → OWASP Web Scan → correlation → report. " +
      "Approved scope: 10.10.50.0/24. No step runs network traffic from this page; Start advances the local simulation only.";
    log("[*] Phase selected: " + phase + " (local view only; nothing executed).");
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
          log("[!!] " + mode + ": file too large (over 1 MiB): " + f.name);
          return;
        }
        log("[+] " + mode + ": loaded local file as data (not executed): " + f.name +
            " (" + f.size + " bytes, " + text.split(/\n/).length + " lines).");
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
    log("[*] Center view: " + (which === "map" ? "Session Map" : "Plan Overview") + ".");
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
    "scan": function () { log("[*] Scan requested for phase " + state.phase + "."); startScan(); },
    "pause": pauseScan,
    "export": exportReport,
    "save": saveState,
    "config": function () { document.getElementById("configDialog").showModal(); },
    "about": function () { document.getElementById("aboutDialog").showModal(); },
    "authorized-note": function () {
      log("[!!] Note: This is an authorized assessment. Do not perform actions outside approved scope (10.10.50.0/24).");
    },
    "copy-plan": function () {
      var text = "Pent3stX SA-2024-011 — passive → active → OWASP Web Scan → correlation → report. Scope 10.10.50.0/24. Checks " + state.checks + "/25.";
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () { log("[+] Plan summary copied to clipboard."); });
      } else { log("[*] Plan summary: " + text); }
    },
    "clear-console": function () {
      consoleBody.textContent = stamp() + "[*] Console cleared (local view).";
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
      log("[*] Port analysis (local data only): 22, 80, 443, 5432 open on 10.10.50.10, .11, .20. No scan was run.");
    },
    "plugins-none": function () { log("[*] Plugins: none loaded (read-only session)."); },
    "show-plan": function () { showTab("plan"); },
    "show-findings": function () { showInspector("findings"); },
    "reset-layout": function () {
      document.getElementById("rightPanel").classList.remove("hidden");
      document.getElementById("consolePanel").classList.remove("collapsed");
      document.getElementById("phaseTree").classList.remove("collapsed");
      showTab("map"); showInspector("pipeline");
      log("[*] Layout reset to the Design Option 1 defaults.");
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

  // Menu dropdowns
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

  // Phase tree
  document.querySelectorAll(".phase").forEach(function (el) {
    el.addEventListener("click", function () { selectPhase(el.getAttribute("data-phase")); });
  });

  // Center tabs + inspector tabs
  document.querySelectorAll(".center-tab").forEach(function (t) {
    t.addEventListener("click", function () { showTab(t.getAttribute("data-center-tab")); });
  });
  document.querySelectorAll(".insp-tab").forEach(function (t) {
    t.addEventListener("click", function () { showInspector(t.getAttribute("data-insp-tab")); });
  });

  // Session map nodes
  document.querySelectorAll(".node").forEach(function (n) {
    n.addEventListener("click", function () {
      log("[*] Host selected on map: " + n.getAttribute("data-host") + " (local view only).");
    });
  });

  // Window controls (web page: no real OS window to minimize)
  document.querySelectorAll(".win-btn").forEach(function (b) {
    b.addEventListener("click", function () {
      var w = b.getAttribute("data-win");
      if (w === "min") log("[*] Minimize is not available for a web page; the workbench stays open.");
      if (w === "max") {
        if (document.fullscreenElement) document.exitFullscreen();
        else if (document.documentElement.requestFullscreen) document.documentElement.requestFullscreen();
        log("[*] Fullscreen toggled.");
      }
      if (w === "close") log("[*] Close is disabled in this read-only view; use the browser tab to leave.");
    });
  });

  // Config toggles
  document.getElementById("optMotion").addEventListener("change", function (ev) {
    document.body.classList.toggle("reduced-motion", ev.target.checked);
    log("[*] Reduced motion " + (ev.target.checked ? "enabled." : "disabled."));
  });
  document.getElementById("optConsole").addEventListener("change", function (ev) {
    document.getElementById("consolePanel").classList.toggle("collapsed", !ev.target.checked);
  });

  loadSavedState();
  render();
})();
