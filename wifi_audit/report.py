"""Markdown and HTML report generation."""

import html
from datetime import date

ICON = {"PASS": "PASS", "WARN": "WARN", "FAIL": "FAIL", "UNKNOWN": "N/A"}
COLOR = {"PASS": "#1a7f37", "WARN": "#b07d00", "FAIL": "#c62828", "UNKNOWN": "#666"}


def _meta(cfg):
    return [
        ("Router brand / model", cfg.get("router_model", "not provided")),
        ("Firmware version", cfg.get("firmware_version", "not provided")),
        ("SSID", cfg.get("ssid", "not provided")),
        ("Review date", cfg.get("review_date", str(date.today()))),
        ("Assessor", cfg.get("assessor", "not provided")),
    ]


def to_markdown(cfg, findings, summary):
    L = ["# Wi-Fi Security Assessment Report", ""]
    L += ["| Item | Value |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in _meta(cfg)]
    L += ["", f"**Score: {summary['score']}/100 - {summary['grade']}**  ",
          f"Passed: {summary['passed']} | Warnings: {summary['warnings']} | "
          f"Failed: {summary['failed']} | Not assessed: {summary['unknown']}", ""]
    L += ["## Findings", "", "| ID | Area | Status | Observed | Expected |", "|---|---|---|---|---|"]
    for f in findings:
        L.append(f"| {f.id} | {f.area} | {ICON[f.status]} | {f.observed} | {f.expected} |")
    todo = [f for f in findings if f.status in ("FAIL", "WARN")]
    L += ["", "## Recommendations (highest impact first)", ""]
    if not todo:
        L.append("No issues found in the assessed items.")
    for i, f in enumerate(sorted(todo, key=lambda x: (x.status != "FAIL", -x.weight)), 1):
        L.append(f"{i}. **{f.area}** ({f.status}) - {f.fix}  \n   *Why:* {f.why}")
    unk = [f for f in findings if f.status == "UNKNOWN"]
    if unk:
        L += ["", "## Not assessed (no data supplied)", ""]
        L += [f"- {f.area}: {f.expected}" for f in unk]
    L += ["", "---", "*Assessment limited to a network owned by the assessor or covered by explicit "
          "authorisation. A configuration review cannot guarantee a network is fully secure.*", ""]
    return "\n".join(L)


def to_html(cfg, findings, summary):
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(f.id)}</td><td>{e(f.area)}</td>"
        f"<td style='color:{COLOR[f.status]};font-weight:700'>{ICON[f.status]}</td>"
        f"<td>{e(str(f.observed))}</td><td>{e(f.expected)}</td></tr>" for f in findings)
    todo = sorted([f for f in findings if f.status in ("FAIL", "WARN")],
                  key=lambda x: (x.status != "FAIL", -x.weight))
    recs = "".join(f"<li><b>{e(f.area)}</b> ({f.status}) &ndash; {e(f.fix)}<br><i>Why:</i> {e(f.why)}</li>"
                   for f in todo) or "<li>No issues found in the assessed items.</li>"
    meta = "".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>" for k, v in _meta(cfg))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Wi-Fi Security Assessment</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{border:1px solid #ccc;padding:6px 10px;text-align:left}}
th{{background:#eef2f7}}.score{{font-size:2rem;font-weight:700}}</style></head><body>
<h1>Wi-Fi Security Assessment Report</h1><table>{meta}</table>
<p class="score">{summary['score']}/100 &ndash; {e(summary['grade'])}</p>
<p>Passed: {summary['passed']} | Warnings: {summary['warnings']} | Failed: {summary['failed']} | Not assessed: {summary['unknown']}</p>
<h2>Findings</h2><table><tr><th>ID</th><th>Area</th><th>Status</th><th>Observed</th><th>Expected</th></tr>{rows}</table>
<h2>Recommendations</h2><ol>{recs}</ol>
<p><small>Assessment limited to a network owned by the assessor or covered by explicit authorisation.
A configuration review cannot guarantee a network is fully secure.</small></p></body></html>"""
