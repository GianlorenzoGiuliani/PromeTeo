"""
Pacchetto dei router.

Ogni file qui dentro raggruppa le pagine di un'area dell'app:
  - home.py     -> la home
  - catalogo.py -> catalogo e gestione di voci/test
  - progetti.py -> progetti (crea/modifica/elimina)
  - findings.py -> findings
  - target.py   -> target (i bersagli di un progetto)
  - report.py   -> report (HTML e Markdown)

main.py li "monta" tutti con app.include_router(...). Dividere le rotte per
area tiene ogni file corto e rende ovvio dove mettere mano per una modifica.
"""
