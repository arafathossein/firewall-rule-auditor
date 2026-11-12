import csv
import io
import ipaddress
import json
from pathlib import Path

import httpx
import pytest

from fw_audit.checks import audit
from fw_audit.cli import main
from fw_audit.model import Addr, Ports
from fw_audit.parsers import parse
from fw_audit.parsers.common import port_list
from fw_audit.report import DeviceAudit, html_report, markdown, to_csv, to_json
from fw_audit.summary import mask_internal, summarise

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "configs"


# ---------- model ----------

def test_addr_covers():
    n = ipaddress.ip_network
    big, small = Addr.of([n("10.0.0.0/8")]), Addr.of([n("10.1.0.0/16")])
    assert big.covers(small) and not small.covers(big)
    assert Addr.anywhere().covers(small) and not small.covers(Addr.anywhere())
    assert not big.covers(Addr.of(names=("list:x",)))
    assert Addr.of([n("0.0.0.0/0")]).any


def test_ports():
    assert port_list("22,80,8000-8100").covers(port_list("8080"))
    assert not port_list("22").covers(port_list("22-23"))
    assert port_list("ssh").ranges == ((22, 22),)
    assert port_list("!22").unknown
    assert Ports.anyport().contains(5) and port_list("1000:2000").contains(1500)


# ---------- parsers ----------

def test_mikrotik_block_export_and_continuation_lines():
    dev = parse("g", (SAMPLES / "branch-gw.rsc").read_text())
    winbox = dev.rules[3]
    assert winbox.src.names == ("list:mgmt",) and winbox.dst_ports.ranges == ((8291, 8291),)
    assert winbox.comment == "Winbox from management network"
    assert [r.ruleset for r in dev.rules].count("input") == 7


def test_cisco_parsing_details():
    dev = parse("c", (SAMPLES / "core-sw.cfg").read_text())
    outside = [r for r in dev.rules if r.ruleset == "OUTSIDE-IN"]
    assert all(r.from_untrusted for r in outside)
    assert outside[0].established_only
    assert outside[1].dst_ports.ranges == ((80, 80), (443, 443)) and outside[1].comment == "public website"
    std = [r for r in dev.rules if r.ruleset == "10"][0]
    assert std.src.nets == (ipaddress.ip_network("10.10.99.20/32"),) and std.comment == "SNMP pollers"


def test_cisco_wildcards_and_operators():
    dev = parse("c", "ip access-list extended X\n permit tcp 10.0.0.0 0.0.255.255 any gt 1023\n permit udp any any range 5000 5010\n"
                     " permit tcp any eq 1234 any eq 22\n", "cisco_ios")
    a, b, c = dev.rules
    assert a.src.nets == (ipaddress.ip_network("10.0.0.0/16"),) and a.dst_ports.ranges == ((1024, 65535),)
    assert b.dst_ports.ranges == ((5000, 5010),)
    assert c.dst_ports.ranges == ((22, 22),) and c.narrowed  # source port limits it


def test_junos_resolves_address_book_and_applications():
    dev = parse("j", (SAMPLES / "dc-srx.cfg").read_text())
    db = next(r for r in dev.rules if r.name == "partner-db")
    assert db.dst.nets == (ipaddress.ip_network("10.30.0.60/32"),) and db.dst_ports.ranges == ((3306, 3306),)
    assert db.protocol == "tcp" and db.from_untrusted and db.comment == "Partner reporting access"
    assert next(r for r in dev.rules if r.name == "old-ftp").disabled


def test_iptables_details():
    dev = parse("w", (SAMPLES / "web-01.rules").read_text())
    assert dev.rulesets["INPUT"].default_action == "allow" and dev.rulesets["FORWARD"].default_action == "deny"
    lo, est = dev.rules[0], dev.rules[1]
    assert lo.in_iface == "lo" and not lo.from_untrusted
    assert est.established_only
    assert dev.rules[2].dst_ports.ranges == ((80, 80), (443, 443))


# ---------- summary and reports ----------

def _audits():
    out = []
    for p in sorted(SAMPLES.iterdir()):
        dev = parse(p.stem, p.read_text())
        f = audit(dev)
        h, a, s = summarise(dev.name, f)
        out.append(DeviceAudit(dev, f, h, a, s))
    return out


def test_rule_summary_names_what_to_fix_first():
    a = next(x for x in _audits() if x.device.name == "web-01")
    assert a.headline == "web-01: 3 high and 0 medium issues"
    assert a.actions[0].startswith("Fix first: Redis open to the internet")


def test_reports_are_consistent():
    audits = _audits()
    data = json.loads(to_json(audits))
    total = sum(len(d["findings"]) for d in data["devices"])
    rows = list(csv.DictReader(io.StringIO(to_csv(audits))))
    assert len(rows) == total
    md = markdown(audits)
    assert md.count("### ") == total
    assert "<script" not in html_report(audits)


def test_html_escapes_rule_text():
    dev = parse("x", "ip access-list extended A\n remark <script>alert(1)</script>\n permit tcp any any eq 23\n", "cisco_ios")
    f = audit(dev)
    assert "<script>" not in html_report([DeviceAudit(dev, f, "h", [], "rules")])


def test_mask_internal_keeps_public_addresses():
    assert mask_internal("10.1.2.3 to 203.0.113.5 and 192.168.0.0/16") == "[internal] to 203.0.113.5 and [internal]"


def _llm(handler):
    return {"base_url": "http://llm.test/v1", "model": "m", "client": httpx.Client(transport=httpx.MockTransport(handler))}


def test_model_summary_masks_internal_ips_in_the_request():
    seen = {}

    def handler(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(
            {"headline": "Redis and every TCP port are open", "actions": ["Close Redis to the internet."]})}}]})

    dev = parse("w", (SAMPLES / "web-01.rules").read_text())
    h, a, src = summarise("w", audit(dev), _llm(handler))
    assert src == "model" and h.startswith("Redis")
    assert "192.0.2" in seen["body"] or "any" in seen["body"]  # public documentation range may appear
    assert "10.30" not in seen["body"]


def test_model_failure_falls_back():
    dev = parse("w", (SAMPLES / "web-01.rules").read_text())
    h, a, src = summarise("w", audit(dev), _llm(lambda r: httpx.Response(500)))
    assert src == "rules (model failed)" and h.startswith("w:")


# ---------- CLI ----------

def test_cli_scan_fail_on_and_ignore(tmp_path, capsys):
    f = str(SAMPLES / "web-01.rules")
    assert main(["scan", f, "--out", str(tmp_path), "--fail-on", "high"]) == 2
    assert main(["scan", f, "--out", str(tmp_path), "--fail-on", "high",
                 "--ignore", "exposed-service,all-ports-open,default-allow"]) == 0
    for ext in ("md", "html", "json", "csv"):
        assert (tmp_path / f"fw-audit.{ext}").exists()
    assert main(["scan", f, "--out", str(tmp_path), "--ignore", "nope"]) == 1


def test_cli_demo(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    assert main(["demo", "--out", str(tmp_path)]) == 0
    assert len(json.loads((tmp_path / "fw-audit.json").read_text())["devices"]) == 4


def test_cli_missing_file(tmp_path):
    assert main(["scan", str(tmp_path / "nope.cfg"), "--out", str(tmp_path)]) == 1
