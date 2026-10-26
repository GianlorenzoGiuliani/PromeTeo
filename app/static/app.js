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
  var here = location.pathname;
  document.querySelectorAll(".bottomnav a[data-match]").forEach(function (a) {
    var m = a.getAttribute("data-match");
    if (here === m || here.indexOf(m + "/") === 0) a.classList.add("active");
  });

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
