from datetime import datetime
from html import escape

from core.helpers import sids_to_names


def render_html(results: list[dict]) -> str:
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    pct = (passed / total * 100) if total else 0.0

    def display(value):
        """
        Traduce SIDs a nombres legibles y luego escapa para HTML.
        Si no hay SIDs, devuelve el valor tal cual.
        """
        if value is None:
            text = ""
        else:
            text = str(value)

        pretty = sids_to_names(text)
        return escape(pretty)

    rows_html = "\n".join(
        f"""
        <tr class="{ 'pass' if r['pass'] else 'fail' }">
          <td class="mono">{escape(r['cis_id'])}</td>
          <td>{escape(r['title'])}</td>
          <td>{display(r['expected'])}</td>
          <td>{display(r['current'])}</td>
          <td>
            <span class="status-pill { 'ok' if r['pass'] else 'bad' }">
              {'PASS' if r['pass'] else 'FAIL'}
            </span>
          </td>
          <td class="evidence">{escape(str(r['evidence']))}</td>
        </tr>
        """
        for r in results
    )

    generated = datetime.now().isoformat(sep=" ", timespec="seconds")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>CIS Windows Server 2025 L1 Compliance Report</title>
<style>
  :root {{
    --bg: #f6f7fb;
    --card: #ffffff;
    --text: #0f172a;
    --muted: #64748b;
    --border: #e2e8f0;

    --accent: #2563eb;
    --accent-soft: rgba(37, 99, 235, 0.10);

    --pass: #16a34a;
    --pass-soft: rgba(22, 163, 74, 0.10);

    --fail: #dc2626;
    --fail-soft: rgba(220, 38, 38, 0.10);

    --shadow: 0 1px 2px rgba(15, 23, 42, 0.06);
    --radius: 14px;
  }}

  * {{ box-sizing: border-box; }}

  body {{
    margin: 0;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Noto Sans", "Liberation Sans", sans-serif;
    background: var(--bg);
    color: var(--text);
  }}

  .page {{
    max-width: 1240px;
    margin: 24px auto 40px;
    padding: 0 16px;
  }}

  .topbar {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 14px;
  }}

  .title {{
    display: flex;
    flex-direction: column;
    gap: 6px;
  }}

  h1 {{
    margin: 0;
    font-size: 18px;
    font-weight: 650;
    letter-spacing: 0.2px;
  }}

  .subtitle {{
    margin: 0;
    font-size: 12px;
    color: var(--muted);
    line-height: 1.4;
  }}

  .meta {{
    text-align: right;
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 220px;
  }}

  .chip {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: fit-content;
    gap: 8px;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--card);
    box-shadow: var(--shadow);
    font-size: 11px;
    color: var(--muted);
  }}

  .chip b {{
    color: var(--text);
    font-weight: 650;
  }}

  .grid {{
    display: grid;
    grid-template-columns: 2fr 1fr 1fr 1fr;
    gap: 12px;
    margin: 12px 0 16px;
  }}

  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 14px 14px;
  }}

  .card .label {{
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }}

  .card .value {{
    margin-top: 8px;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.2px;
  }}

  .card .hint {{
    margin-top: 6px;
    font-size: 12px;
    color: var(--muted);
  }}

  .overview {{
    display: flex;
    flex-direction: column;
    gap: 10px;
  }}

  .overview .headline {{
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
  }}

  .overview .pct {{
    font-size: 28px;
    font-weight: 800;
    letter-spacing: -0.4px;
  }}

  .bar {{
    width: 100%;
    height: 10px;
    background: #eef2ff;
    border: 1px solid rgba(37,99,235,0.18);
    border-radius: 999px;
    overflow: hidden;
  }}

  .bar > div {{
    height: 100%;
    width: {pct:.1f}%;
    background: linear-gradient(90deg, var(--accent), #1d4ed8);
  }}

  .kpis {{
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
  }}

  .kpi-pill {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: #fafafa;
    font-size: 12px;
    color: var(--muted);
  }}
  .dot {{
    width: 8px;
    height: 8px;
    border-radius: 99px;
    background: var(--muted);
  }}
  .dot.ok {{ background: var(--pass); }}
  .dot.bad {{ background: var(--fail); }}
  .kpi-pill b {{
    color: var(--text);
    font-weight: 650;
  }}

  .controls {{
    display: grid;
    grid-template-columns: 180px 180px 1fr;
    gap: 10px;
    margin: 12px 0 10px;
  }}

  .field {{
    display: flex;
    flex-direction: column;
    gap: 6px;
  }}

  .field label {{
    font-size: 12px;
    color: var(--muted);
    font-weight: 600;
  }}

  select, input {{
    appearance: none;
    width: 100%;
    padding: 10px 12px;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--text);
    font-size: 13px;
    outline: none;
    box-shadow: var(--shadow);
  }}

  select:focus, input:focus {{
    border-color: rgba(37,99,235,0.55);
    box-shadow: 0 0 0 4px rgba(37,99,235,0.12);
  }}

  .table-wrap {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    overflow: hidden;
  }}

  .scroll {{
    overflow-x: visible;
  }}

  table {{
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    min-width: 980px;
    table-layout: auto;
  }}

  thead th {{
    position: sticky;
    top: 0;
    z-index: 2;
    background: #fbfcff;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    padding: 12px 12px;
    text-align: left;
    white-space: nowrap;
  }}

  tbody td {{
    padding: 12px 12px;
    font-size: 13px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    color: var(--text);
    white-space: normal;
    word-break: break-word;
    overflow-wrap: anywhere;
  }}

  thead th:nth-child(1),
  tbody td:nth-child(1) {{
    width: 110px;
    min-width: 110px;
    white-space: nowrap;
  }}

  thead th:nth-child(5),
  tbody td:nth-child(5) {{
    width: 90px;
    min-width: 90px;
    white-space: nowrap;
    text-align: center;
  }}

  tbody tr:nth-child(even) td {{
    background: #fafafa;
  }}

  tbody tr:hover td {{
    background: #f8fafc;
  }}

  tbody tr.pass td:first-child {{
    border-left: 4px solid var(--pass);
  }}
  tbody tr.fail td:first-child {{
    border-left: 4px solid var(--fail);
  }}

  .mono {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-weight: 650;
    white-space: nowrap;
    word-break: normal;
    overflow-wrap: normal;
  }}

  .status-pill {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 6px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.04em;
    border: 1px solid var(--border);
    background: #fff;
    min-width: 68px;
    white-space: nowrap;
    line-height: 1;
    text-align: center;
  }}

  .status-pill.ok {{
    color: var(--pass);
    border-color: rgba(22,163,74,0.28);
    background: var(--pass-soft);
  }}

  .status-pill.bad {{
    color: var(--fail);
    border-color: rgba(220,38,38,0.28);
    background: var(--fail-soft);
  }}

  .evidence {{
    color: #334155;
    white-space: normal;
    word-break: break-word;
    overflow-wrap: anywhere;
  }}

  .footnote {{
    margin-top: 12px;
    color: var(--muted);
    font-size: 12px;
    line-height: 1.5;
  }}

  @media (max-width: 900px) {{
    .grid {{
      grid-template-columns: 1fr;
    }}
    .controls {{
      grid-template-columns: 1fr;
    }}
    .meta {{
      text-align: left;
      min-width: auto;
    }}
    .topbar {{
      flex-direction: column;
      align-items: flex-start;
    }}
  }}
</style>
</head>
<body>
  <div class="page">
    <div class="topbar">
      <div class="title">
        <h1>CIS Microsoft Windows Server 2025 – Level 1 (Member Server) Compliance</h1>
        <p class="subtitle">Automated assessment of selected CIS benchmark security controls for this server.</p>
      </div>
      <div class="meta">
        <div class="chip"><b>Compliance Report</b></div>
        <div class="chip">Generated: <b>{generated}</b></div>
      </div>
    </div>

    <div class="grid">
      <div class="card overview">
        <div class="headline">
          <div>
            <div class="label">Overall compliance</div>
            <div class="pct">{pct:.1f}%</div>
          </div>
          <div class="kpis">
            <span class="kpi-pill"><span class="dot ok"></span>Passed: <b>{passed}</b></span>
            <span class="kpi-pill"><span class="dot bad"></span>Failed: <b>{failed}</b></span>
            <span class="kpi-pill"><span class="dot"></span>Total: <b>{total}</b></span>
          </div>
        </div>
        <div class="bar" aria-label="Compliance progress"><div></div></div>
        <div class="hint">Passing checks versus total evaluated controls.</div>
      </div>

      <div class="card">
        <div class="label">Total checks</div>
        <div class="value">{total}</div>
        <div class="hint">Rules evaluated on this host.</div>
      </div>

      <div class="card">
        <div class="label">Passed</div>
        <div class="value">{passed}</div>
        <div class="hint">Aligned with CIS guidance.</div>
      </div>

      <div class="card">
        <div class="label">Failed</div>
        <div class="value">{failed}</div>
        <div class="hint">Require remediation.</div>
      </div>
    </div>

    <div class="controls">
      <div class="field">
        <label for="statusFilter">Estado</label>
        <select id="statusFilter">
          <option value="all">Todos</option>
          <option value="pass">Solo PASS</option>
          <option value="fail">Solo FAIL</option>
        </select>
      </div>

      <div class="field">
        <label for="sectionFilter">Sección CIS</label>
        <select id="sectionFilter">
          <option value="all">Todas</option>
        </select>
      </div>

      <div class="field">
        <label for="searchBox">Buscar</label>
        <input id="searchBox" type="text" placeholder="Buscar por CIS ID, recomendación, evidencia..." />
      </div>
    </div>

    <div class="table-wrap">
      <div class="scroll">
        <table id="resultsTable">
          <thead>
            <tr>
              <th>CIS ID</th>
              <th>Recommendation</th>
              <th>Expected</th>
              <th>Current</th>
              <th>Status</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
      </div>
    </div>

    <div class="footnote">
      Nota: este reporte incluye solo un subconjunto inicial de recomendaciones L1 automatizables.
      Puedes ampliar la lista agregando más reglas L1 del benchmark.
    </div>
  </div>

  <script>
    (function() {{
      const statusFilter = document.getElementById('statusFilter');
      const sectionFilter = document.getElementById('sectionFilter');
      const searchBox = document.getElementById('searchBox');
      const table = document.getElementById('resultsTable');
      const rows = Array.from(table.querySelectorAll('tbody tr'));

      const getSectionFromId = (cisId) => {{
        if (!cisId) return '';
        const parts = cisId.split('.');
        if (parts.length >= 2) return parts[0] + '.' + parts[1];
        return cisId;
      }};

      // Fill sections
      const sections = new Set();
      rows.forEach(row => {{
        const cisId = row.cells[0]?.textContent.trim();
        if (cisId) sections.add(getSectionFromId(cisId));
      }});
      Array.from(sections).sort().forEach(sec => {{
        const opt = document.createElement('option');
        opt.value = sec;
        opt.textContent = sec;
        sectionFilter.appendChild(opt);
      }});

      function applyFilters() {{
        const statusVal = statusFilter.value;
        const sectionVal = sectionFilter.value;
        const q = searchBox.value.trim().toLowerCase();

        rows.forEach(row => {{
          const rowStatus = row.classList.contains('pass')
            ? 'pass'
            : (row.classList.contains('fail') ? 'fail' : '');

          const cisId = row.cells[0]?.textContent || '';
          const sectionId = getSectionFromId(cisId);
          const text = row.textContent.toLowerCase();

          let visible = true;

          if (statusVal !== 'all' && rowStatus !== statusVal) visible = false;
          if (visible && sectionVal !== 'all' && sectionId !== sectionVal) visible = false;
          if (visible && q && !text.includes(q)) visible = false;

          row.style.display = visible ? '' : 'none';
        }});
      }}

      statusFilter.addEventListener('change', applyFilters);
      sectionFilter.addEventListener('change', applyFilters);
      searchBox.addEventListener('input', applyFilters);
    }})();
  </script>
</body>
</html>"""