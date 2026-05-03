import sys
from pathlib import Path

from core.helpers import is_admin
from checks.all_checks import rules
from reports.html_reporter import render_html


def main():
    print("Ejecutando auditoría CIS Windows Server 2025 Level 1...")
    print("Este proceso puede tomar unos segundos...")

    if not is_admin():
        print("ERROR: Este script debe ejecutarse como Administrador")
        print("Por favor, abre PowerShell o CMD como Administrador y ejecuta nuevamente")
        sys.exit(1)

    # Verificar que no hay reglas None
    for i, rule in enumerate(rules):
        if rule is None:
            print(f"ERROR: La regla en la posición {i} es None")
            return

    results = []
    for i, rule in enumerate(rules, 1):
        print(f"Verificando regla {i}/{len(rules)}: {rule.cis_id}")
        results.append(rule.evaluate())

    html = render_html(results)
    out_path = Path.cwd() / "CIS_WS2025_L1_Report.html"
    out_path.write_text(html, encoding="utf-8")
    print(f"\nReporte generado: {out_path}")


if __name__ == "__main__":
    main()
