"""Short summary for a manager: what's wrong and what to fix first.

Always available from the findings alone. Optionally rewritten by any
OpenAI-compatible model (a local Ollama works); internal addresses can be
masked before anything is sent.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re

import httpx

from .model import Finding, Severity

log = logging.getLogger("fw_audit")
# Internal ranges only; documentation and public addresses are kept.
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                               "169.254.0.0/16", "100.64.0.0/10")]
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


def counts(findings: list[Finding]) -> dict[str, int]:
    c = {s.value: 0 for s in reversed(Severity)}
    for f in findings:
        c[f.severity.value] += 1
    return c


def rule_summary(device: str, findings: list[Finding]) -> tuple[str, list[str]]:
    c = counts(findings)
    if not findings:
        return f"{device}: no issues found by the checks", []
    serious = [f for f in findings if f.severity in (Severity.high, Severity.medium)]
    headline = (f"{device}: {c['high']} high and {c['medium']} medium issues" if serious
                else f"{device}: housekeeping only ({len(findings)} low or info items)")
    first = []
    seen = set()
    for f in serious:
        if f.title in seen:
            continue
        seen.add(f.title)
        where = f.rule.label if f.rule else f.ruleset
        first.append(f"Fix first: {f.title} ({where}).")
        if len(first) == 3:
            break
    return headline, first


def mask_internal(text: str) -> str:
    def sub(m: re.Match[str]) -> str:
        try:
            ip = ipaddress.ip_network(m.group(0), strict=False)
        except ValueError:
            return m.group(0)
        return "[internal]" if any(ip.version == 4 and ip.subnet_of(n) for n in _INTERNAL) else m.group(0)

    return _IP.sub(sub, text)


_SYSTEM = """You summarise a firewall audit for an IT manager. You get the device name and findings
(severity, title, detail). Reply with JSON only: {"headline": str (max 100 chars), "actions": [str, ...] (2-4 items)}.
Each action is one plain sentence saying what to change first and why. Use only facts in the findings.
Do not claim anything was fixed or exploited."""


def llm_summary(device: str, findings: list[Finding], base_url: str, api_key: str, model: str,
                mask: bool = True, client: httpx.Client | None = None) -> tuple[str, list[str]]:
    items = [{"severity": f.severity.value, "title": f.title, "detail": mask_internal(f.detail) if mask else f.detail}
             for f in findings if f.severity != Severity.info][:40]
    client = client or httpx.Client(timeout=60)
    resp = client.post(
        f"{base_url.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
        json={"model": model, "temperature": 0.1, "response_format": {"type": "json_object"},
              "messages": [{"role": "system", "content": _SYSTEM},
                           {"role": "user", "content": json.dumps({"device": device, "findings": items})}]},
    )
    resp.raise_for_status()
    content = re.sub(r"^```(?:json)?\s*|\s*```$", "", resp.json()["choices"][0]["message"]["content"].strip())
    data = json.loads(content)
    headline = str(data["headline"]).strip()[:120]
    actions = [str(a).strip() for a in data.get("actions", []) if str(a).strip()][:4]
    if not headline or not actions:
        raise ValueError("empty summary")
    return headline, actions


def summarise(device: str, findings: list[Finding], llm: dict | None = None) -> tuple[str, list[str], str]:
    """Returns (headline, actions, source)."""
    if llm and llm.get("base_url") and findings:
        try:
            h, a = llm_summary(device, findings, llm["base_url"], llm.get("api_key", ""), llm.get("model", "llama3.1:8b"),
                               llm.get("mask", True), llm.get("client"))
            return h, a, "model"
        except Exception as exc:  # noqa: BLE001 - any model failure falls back
            log.warning("model summary failed for %s: %s", device, exc)
            h, a = rule_summary(device, findings)
            return h, a, "rules (model failed)"
    h, a = rule_summary(device, findings)
    return h, a, "rules"
