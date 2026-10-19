"""Interactive HTML report generator (Jinja2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from jinja2 import Template

from ..core.context import ScanContext
from .json_report import build_report_dict

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>corvid_ad report — {{ report.metadata.domain }}</title>
<style>
:root{--bg:#0f1419;--panel:#1a2029;--border:#2a3441;--fg:#e6edf3;--muted:#8b98a5;
--crit:#ff6b6b;--high:#ffa94d;--med:#ffd43b;--low:#4dabf7;--info:#63e6be;}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--fg);line-height:1.5}
header{padding:24px 32px;border-bottom:1px solid var(--border);background:var(--panel)}
h1{margin:0;font-size:22px}h2{font-size:18px;margin:24px 0 8px}
.meta{color:var(--muted);font-size:13px;margin-top:6px}
.wrap{padding:16px 32px;max-width:1200px;margin:0 auto}
.badges{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.badge{padding:6px 12px;border-radius:6px;font-weight:600;font-size:13px;border:1px solid var(--border)}
.sev-critical{color:var(--crit);border-color:var(--crit)}
.sev-high{color:var(--high);border-color:var(--high)}
.sev-medium{color:var(--med);border-color:var(--med)}
.sev-low{color:var(--low);border-color:var(--low)}
.sev-info{color:var(--info);border-color:var(--info)}
input[type=search]{width:100%;padding:10px 14px;background:var(--panel);border:1px solid var(--border);
color:var(--fg);border-radius:8px;font-size:14px;margin-bottom:16px}
.finding{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:16px;margin-bottom:12px}
.finding h3{margin:0 0 6px;font-size:15px}
.tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:4px;margin-right:6px;
background:#242e3a;color:var(--muted);border:1px solid var(--border)}
.tag.sev{font-weight:700}
.evidence{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:#11161c;
padding:8px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;margin:8px 0;color:#9ecbff}
.section{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:600}
.path{margin:6px 0;padding:8px;background:#11161c;border-radius:6px;font-size:13px}
.hop{color:var(--muted)}.edge{color:var(--high);font-weight:600;padding:0 6px}
.muted{color:var(--muted)}
</style>
</head>
<body>
<header>
  <h1>corvid_ad — Active Directory Assessment Report</h1>
  <div class="meta">
    Domain: <strong>{{ report.metadata.domain or 'n/a' }}</strong> ·
    Mode: {{ report.metadata.mode }} · Source: {{ report.metadata.source }} ·
    Started: {{ report.metadata.started_at }}
  </div>
</header>
<div class="wrap">
  <div class="badges">
    {% set dist = report.metadata.severity_distribution %}
    <span class="badge sev-critical">Critical {{ dist.critical }}</span>
    <span class="badge sev-high">High {{ dist.high }}</span>
    <span class="badge sev-medium">Medium {{ dist.medium }}</span>
    <span class="badge sev-low">Low {{ dist.low }}</span>
    <span class="badge sev-info">Info {{ dist.info }}</span>
    <span class="badge">Total {{ report.metadata.findings_count }}</span>
  </div>

  <div class="section">
    <h2>Collection</h2>
    {% set c = report.collection %}
    <div class="meta">Users {{ c.users }} · Groups {{ c.groups }} · Computers {{ c.computers }} ·
    GPOs {{ c.gpos }} · CAs {{ c.cas }} · Templates {{ c.templates }} · Trusts {{ c.trusts }} ·
    Complete: {{ 'yes' if c.complete else 'no' }}</div>
    {% if c.warnings %}<div class="evidence">{{ c.warnings | join('\n') }}</div>{% endif %}
  </div>

  {% if report.attack_paths %}
  <div class="section">
    <h2>Attack Paths (high-value targets)</h2>
    {% for p in report.attack_paths %}
    <div class="path">
      <strong>→ {{ p.target }}</strong> ({{ p.length }} hops)
      <div>
      {% for h in p.hops %}
        <span class="hop">{{ h.from }}</span><span class="edge">—{{ h.edge }}→</span>
      {% endfor %}
      <span class="hop">{{ p.target }}</span>
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <h2>Findings</h2>
  <input type="search" id="filter" placeholder="Search findings (title, principal, object, category)..." oninput="filterFindings(this.value)">
  <div id="findings">
  {% for f in report.findings %}
  <div class="finding" data-search="{{ (f.title + ' ' + (f.affected_principal or '') + ' ' + (f.affected_object or '') + ' ' + f.category) | lower }}">
    <h3><span class="tag sev sev-{{ f.severity }}">{{ f.severity | upper }}</span>
        <span class="tag">{{ f.category }}</span>
        <span class="tag">conf: {{ f.confidence }}</span>
        {{ f.title }}</h3>
    {% if f.affected_principal %}<div class="meta">Principal: <strong>{{ f.affected_principal }}</strong></div>{% endif %}
    {% if f.affected_object %}<div class="meta">Object: <code>{{ f.affected_object }}</code></div>{% endif %}
    {% if f.impact %}<div class="meta">Impact: {{ f.impact }}</div>{% endif %}
    {% if f.evidence %}<div class="evidence">{{ f.evidence | tojson(indent=2) }}</div>{% endif %}
    {% if f.manual_verification %}<div class="meta">Verify: {{ f.manual_verification | join('; ') }}</div>{% endif %}
    {% if f.remediation %}<div class="meta">Remediate: {{ f.remediation | join('; ') }}</div>{% endif %}
    {% if f.references %}<div class="meta">Refs: {{ f.references | join('; ') }}</div>{% endif %}
  </div>
  {% endfor %}
  </div>
</div>
<script>
function filterFindings(q){
  q=q.toLowerCase();
  document.querySelectorAll('.finding').forEach(el=>{
    el.style.display = el.dataset.search.includes(q) ? '' : 'none';
  });
}
</script>
</body>
</html>
"""


def write_html(ctx: ScanContext, out_dir: str | Path, graph: Optional[Any] = None,
               paths: Optional[list] = None) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = build_report_dict(ctx, graph, paths)
    html = Template(_TEMPLATE).render(report=report)
    path = out / "report.html"
    path.write_text(html, encoding="utf-8")
    return path
