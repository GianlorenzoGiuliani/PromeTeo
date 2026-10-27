// JavaScript lato browser di Prometeo.
//
// A differenza del resto dell'app (che gira sul server), questo codice gira
// nel browser dell'utente. Fa due cose:
//   1) il tasto "Copia" sui blocchi di comando/payload;
//   2) nel form "nuovo finding" globale, aggiorna il menu dei target quando
//      cambi il progetto scelto;
//   3) l'assistente AI: manda la descrizione al server e riempie i campi.
//
// 'DOMContentLoaded' = aspetta che la pagina sia caricata prima di agire.
document.addEventListener("DOMContentLoaded", function () {

  // --- 1) Tasto "Copia" ---
  document.querySelectorAll(".copy-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var block = btn.closest(".cmd-block");
      var code = block ? block.querySelector("pre.cmd code") : null;
      if (!code) return;
      // navigator.clipboard copia negli appunti (funziona su https e su localhost).
      navigator.clipboard.writeText(code.innerText).then(
        function () {
          var original = btn.textContent;
          btn.textContent = "Copiato!";
          setTimeout(function () { btn.textContent = original; }, 1200);
        },
        function () {
          btn.textContent = "Errore";
          setTimeout(function () { btn.textContent = "Copia"; }, 1200);
        }
      );
    });
  });

  // --- 2) Menu dei target dipendente dal progetto ---
  var dataEl = document.getElementById("targets-by-project");
  var projSel = document.querySelector("select.js-project");
  var targSel = document.querySelector("select.js-target");
  if (dataEl && projSel && targSel) {
    var byProject = {};
    try { byProject = JSON.parse(dataEl.textContent || "{}"); } catch (e) { byProject = {}; }
    // Il target da ri-selezionare (es. tornando al form con un errore).
    var preselect = targSel.getAttribute("data-selected") || "";

    function fillTargets() {
      var list = byProject[projSel.value] || [];
      targSel.innerHTML = "";
      var none = document.createElement("option");
      none.value = "";
      none.textContent = "— nessuno —";
      targSel.appendChild(none);
      list.forEach(function (t) {
        var opt = document.createElement("option");
        opt.value = t.id;
        opt.textContent = t.label;
        if (String(t.id) === String(preselect)) opt.selected = true;
        targSel.appendChild(opt);
      });
    }

    projSel.addEventListener("change", fillTargets);
    fillTargets();  // riempi subito in base al progetto gia' selezionato
  }

  // --- 3) Assistente AI: precompila il form da una descrizione ---
  // Scrive i valori suggeriti nei campi del form, poi tocca all'utente
  // controllare e correggere prima di salvare.
  function fillFinding(form, fields) {
    if (!form || !fields) return;
    Object.keys(fields).forEach(function (name) {
      var value = fields[name];
      if (value === null || value === undefined || value === "") return;
      var el = form.elements[name];
      if (el) el.value = value;  // su una <select> seleziona l'opzione giusta
    });
  }

  var aiBtn = document.getElementById("ai-btn");
  if (aiBtn) {
    aiBtn.addEventListener("click", function () {
      var descEl = document.getElementById("ai-desc");
      var statusEl = document.getElementById("ai-status");
      var form = aiBtn.closest("form");
      var desc = ((descEl && descEl.value) || "").trim();
      if (!desc) {
        if (statusEl) statusEl.textContent = "Scrivi prima una breve descrizione.";
        return;
      }
      var tokenEl = form ? form.querySelector('input[name="csrf_token"]') : null;
      var body = new URLSearchParams({
        description: desc,
        csrf_token: tokenEl ? tokenEl.value : "",
      });
      aiBtn.disabled = true;
      if (statusEl) statusEl.textContent = "Sto generando…";
      fetch(aiBtn.dataset.url, { method: "POST", body: body })
        .then(function (res) { return res.json(); })
        .then(function (data) {
          if (!data.ok) {
            if (statusEl) statusEl.textContent = data.error || "Errore.";
            return;
          }
          fillFinding(form, data.fields);
          if (statusEl) statusEl.textContent = "Fatto! Controlla e correggi prima di salvare.";
        })
        .catch(function () {
          if (statusEl) statusEl.textContent = "Errore di rete.";
        })
        .finally(function () { aiBtn.disabled = false; });
    });
  }

  // --- 5) Barra-menu in basso: evidenzia la sezione in cui ti trovi ---
  // Match per percorso (es. /porte) e, nelle pagine di dettaglio (/topic/..),
  // tramite un marcatore nascosto che indica la sezione di appartenenza.
  var here = location.pathname;
  var marker = document.querySelector(".js-section");
  var section = marker ? marker.getAttribute("data-match") : null;
  document.querySelectorAll(".bottomnav a[data-match]").forEach(function (a) {
    var m = a.getAttribute("data-match");
    if (here === m || here.indexOf(m + "/") === 0 || m === section) a.classList.add("active");
  });

  // --- 6) Compilazione automatica dei comandi (solo sezione Porte) ---
  // Ogni comando del catalogo porte contiene dei segnaposto (es. IP, <ip>,
  // DOMINIO, UTENTE...). Qui riconosciamo quali servono a un comando, mostriamo
  // un campo per ciascuno e aggiorniamo in tempo reale il comando compilato.
  // Tutto lato browser: l'app non esegue nulla, tu copi il comando pronto.
  if (section === "/porte") {
    // Dizionario dei segnaposto riconosciuti: chiave logica, etichetta,
    // esempio e il pattern (anche piu' forme per lo stesso valore).
    var VARS = [
      { key: "PORTE",    label: "Porte",     ph: "80,443,8080",       pat: "porta1,porta2,porta3", save: true },
      { key: "DC_IP",    label: "IP Domain Controller", ph: "10.0.0.1", pat: "\\bIP_DC\\b",        save: true },
      { key: "IP",       label: "IP bersaglio", ph: "10.0.0.5",       pat: "<ip>|\\bIP\\b",        save: true },
      { key: "URL",      label: "URL",       ph: "http://10.0.0.5/",  pat: "<url>",                save: true },
      { key: "DOMINIO",  label: "Dominio",   ph: "dominio.local",     pat: "<dominio>|\\bDOMINIO\\b", save: true },
      { key: "ZONA",     label: "Zona DNS",  ph: "dominio.local",     pat: "\\bZONA\\b",           save: true },
      { key: "SHARE",    label: "Nome share", ph: "C$",               pat: "\\bNOMESHARE\\b",      save: true },
      { key: "HOST",     label: "Host/dominio", ph: "sito.local",     pat: "\\bNOME\\b",           save: true },
      { key: "UTENTE",   label: "Utente",    ph: "administrator",     pat: "\\bUTENTE\\b|\\butente\\b", save: false },
      { key: "PASSWORD", label: "Password",  ph: "la password",       pat: "\\bPASSWORD\\b|\\bpassword\\b", save: false },
      { key: "TOKEN",    label: "API token", ph: "",                  pat: "\\bTUO_TOKEN\\b",      save: false },
    ];
    var STORE_KEY = "porte_valori";

    function loadValues() {
      try { return JSON.parse(localStorage.getItem(STORE_KEY) || "{}"); } catch (e) { return {}; }
    }
    function saveValues(values) {
      // Salviamo solo i valori "non sensibili" (no password/token).
      var safe = {};
      VARS.forEach(function (v) { if (v.save && values[v.key]) safe[v.key] = values[v.key]; });
      try { localStorage.setItem(STORE_KEY, JSON.stringify(safe)); } catch (e) {}
    }
    function fill(template, values) {
      var out = template;
      VARS.forEach(function (v) {
        var val = values[v.key];
        if (val) out = out.replace(new RegExp(v.pat, "g"), val);
      });
      return out;
    }

    var values = loadValues();
    var blocks = [];  // { code, template }

    document.querySelectorAll(".cmd-block").forEach(function (block) {
      var code = block.querySelector("pre.cmd code");
      if (!code) return;
      var template = code.textContent;
      var used = VARS.filter(function (v) { return new RegExp(v.pat).test(template); });
      if (!used.length) return;  // comando senza segnaposto: lo lasciamo com'e'

      var panel = document.createElement("div");
      panel.className = "cmd-fields";
      used.forEach(function (v) {
        var lab = document.createElement("label");
        lab.textContent = v.label;
        var inp = document.createElement("input");
        inp.type = "text";
        inp.placeholder = v.ph || "";
        inp.value = values[v.key] || "";
        inp.setAttribute("data-key", v.key);
        inp.addEventListener("input", function () {
          values[v.key] = inp.value;
          saveValues(values);
          // sincronizza gli altri campi con la stessa variabile sulla pagina
          document.querySelectorAll('.cmd-fields input[data-key="' + v.key + '"]').forEach(function (other) {
            if (other !== inp && other.value !== inp.value) other.value = inp.value;
          });
          renderAll();
        });
        lab.appendChild(inp);
        panel.appendChild(lab);
      });
      block.insertBefore(panel, block.querySelector("pre.cmd"));
      blocks.push({ code: code, template: template });
    });

    function renderAll() {
      blocks.forEach(function (b) { b.code.textContent = fill(b.template, values); });
    }
    renderAll();  // compila subito con gli eventuali valori salvati
  }

  // --- 4) Interruttore tema chiaro/scuro ---
  var themeBtn = document.getElementById("theme-toggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var root = document.documentElement;
      var current = root.getAttribute("data-theme") === "light" ? "light" : "dark";
      var next = current === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("tema", next); } catch (e) {}
    });
  }
});
