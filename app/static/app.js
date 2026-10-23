// JavaScript lato browser di PromeTeus.
//
// A differenza del resto dell'app (che gira sul server), questo codice gira
// nel browser dell'utente. Per ora fa una cosa sola: il tasto "Copia" sui
// blocchi di comando/payload.
//
// 'DOMContentLoaded' = aspetta che la pagina sia caricata prima di agire.
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".copy-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      // Troviamo il blocco di codice vicino al pulsante.
      var block = btn.closest(".cmd-block");
      var code = block ? block.querySelector("pre.cmd code") : null;
      if (!code) return;

      // navigator.clipboard copia nel appunti (funziona su https e su localhost).
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
});
