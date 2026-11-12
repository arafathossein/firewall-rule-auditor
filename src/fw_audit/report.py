"""Markdown, HTML, JSON and CSV reports."""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import dataclass, field

from .model import Device, Finding
from .summary import counts

ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


@dataclass
class DeviceAudit:
    device: Device
    findings: list[Finding]
    headline: str
    actions: list[str]
    summary_source: str
    ignored: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return counts(self.findings)


def _rule_ref(f: Finding) -> str:
    if f.rule:
        return f"{f.rule.label}, line {f.rule.line_no}"
    return f.ruleset or ""


def markdown(audits: list[DeviceAudit], title: str = "Firewall rule audit") -> str:
    out = [f"# {title}", "", "| Device | Vendor | Rules | 🔴 High | 🟠 Medium | 🟡 Low | ⚪ Info |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for a in audits:
        c = a.counts
        out.append(f"| {a.device.name} | {a.device.vendor} | {len(a.device.rules)} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} |")
    for a in audits:
        out += ["", f"## {a.headline}", ""]
        out += [f"- {x}" for x in a.actions]
        if a.actions:
            out.append("")
        for note in a.device.notes:
            out.append(f"> Note: {note}")
        for f in a.findings:
            out += [f"### {ICON[f.severity.value]} {f.title}", "", f"**{f.severity.value.title()}** · {_rule_ref(f)}", "",
                    f.detail, "", f"**Fix:** {f.fix}"]
            if f.rule:
                out += ["", "```", f.rule.raw, "```"]
            if f.related:
                out += [f"Covered by {f.related.label} (line {f.related.line_no}):", "", "```", f.related.raw, "```"]
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def to_json(audits: list[DeviceAudit]) -> str:
    def rule(r):
        return None if r is None else {"ruleset": r.ruleset, "position": r.position, "line": r.line_no, "name": r.name,
                                       "action": r.action, "raw": r.raw}

    data = []
    for a in audits:
        data.append({
            "device": a.device.name, "vendor": a.device.vendor, "rules": len(a.device.rules), "counts": a.counts,
            "headline": a.headline, "actions": a.actions, "summary_source": a.summary_source, "notes": a.device.notes,
            "ignored_checks": a.ignored,
            "findings": [{"check": f.check, "severity": f.severity.value, "title": f.title, "detail": f.detail, "fix": f.fix,
                          "ruleset": f.ruleset or (f.rule.ruleset if f.rule else None), "rule": rule(f.rule),
                          "related": rule(f.related)} for f in a.findings],
        })
    return json.dumps({"devices": data}, indent=2, ensure_ascii=False)


def to_csv(audits: list[DeviceAudit]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["device", "vendor", "severity", "check", "title", "ruleset", "position", "line", "detail", "fix", "rule"])
    for a in audits:
        for f in a.findings:
            r = f.rule
            w.writerow([a.device.name, a.device.vendor, f.severity.value, f.check, f.title,
                        r.ruleset if r else f.ruleset, r.position if r else "", r.line_no if r else "",
                        f.detail, f.fix, r.raw if r else ""])
    return buf.getvalue()


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#141821;--muted:#5b6170;--line:#e1e4ea;--code:#f0f2f5;
--high:#b42318;--medium:#a85d00;--low:#7a6b00;--info:#5b6170}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--ink:#eef1f6;--muted:#a0a7b4;--line:#2a303b;--code:#1f2430;
--high:#ff8b80;--medium:#f5b64d;--low:#e2d36c;--info:#a0a7b4}}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px 64px}h1{font-size:28px;margin:0 0 16px}
h2{font-size:20px;margin:0 0 8px}h3{font-size:16px;margin:0}.muted{color:var(--muted)}
table{width:100%;border-collapse:collapse;margin:0 0 24px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:500}td.n{font-variant-numeric:tabular-nums}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:16px}
.f{border-top:1px solid var(--line);padding:14px 0}.f:first-of-type{border-top:0}
.sev{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:0 8px;font-size:12px;font-weight:600;margin-right:6px}
.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
code,pre{font:13px/1.5 ui-monospace,Menlo,monospace}pre{background:var(--code);border-radius:8px;padding:8px 12px;overflow-x:auto;margin:8px 0 0}
ul{padding-left:20px;margin:8px 0}
"""


def html_report(audits: list[DeviceAudit], title: str = "Firewall rule audit") -> str:
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(a.device.name)}</td><td>{e(a.device.vendor)}</td><td class=n>{len(a.device.rules)}</td>"
        + "".join(f'<td class="n {k}">{v}</td>' for k, v in a.counts.items()) + "</tr>" for a in audits)
    cards = []
    for a in audits:
        parts = [f'<section class="card"><h2>{e(a.headline)}</h2>']
        if a.actions:
            parts.append("<ul>" + "".join(f"<li>{e(x)}</li>" for x in a.actions) + "</ul>")
        parts.append(f'<p class="muted">Summary by {e(a.summary_source)}.</p>')
        parts += [f'<p class="muted">Note: {e(n)}</p>' for n in a.device.notes]
        for f in a.findings:
            raw = f"<pre>{e(f.rule.raw)}</pre>" if f.rule else ""
            rel = (f'<p class="muted">Covered by {e(f.related.label)} (line {f.related.line_no})</p><pre>{e(f.related.raw)}</pre>'
                   if f.related else "")
            parts.append(f'<div class="f"><h3><span class="sev {f.severity.value}">{f.severity.value}</span>{e(f.title)}</h3>'
                         f'<p class="muted">{e(_rule_ref(f))}</p><p>{e(f.detail)}<br><strong>Fix:</strong> {e(f.fix)}</p>{raw}{rel}</div>')
        parts.append("</section>")
        cards.append("".join(parts))
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{e(title)}</title><style>{_CSS}</style></head><body><main><h1>{e(title)}</h1>"
            f"<table><thead><tr><th>Device</th><th>Vendor</th><th>Rules</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>{''.join(cards)}</main></body></html>\n")
