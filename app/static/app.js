// JavaScript lato browser di PromeTeus.
//
// A differenza del resto dell'app (che gira sul server), questo codice gira
// nel browser dell'utente. Fa due cose:
//   1) il tasto "Copia" sui blocchi di comando/payload;
//   2) nel form "nuovo finding" globale, aggiorna il menu dei target quando
//      cambi il progetto scelto.
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
});
