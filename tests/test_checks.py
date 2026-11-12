from pathlib import Path

import pytest

from fw_audit.checks import audit
from fw_audit.model import Severity
from fw_audit.parsers import detect, parse

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "configs"


def run(text: str, vendor: str):
    return audit(parse("t", text, vendor))


def found(findings):
    return {(f.check, f.rule.label if f.rule else f.ruleset) for f in findings}


def sample(name):
    p = SAMPLES / name
    return audit(parse(p.stem, p.read_text()))


# ---------- the bundled samples, finding by finding ----------

def test_sample_mikrotik():
    assert found(sample("branch-gw.rsc")) == {
        ("exposed-service", "input #5"), ("exposed-service", "forward #3"), ("default-allow", "input"),
        ("no-comment", "input #5"), ("disabled", "input #7")}


def test_sample_cisco():
    assert found(sample("core-sw.cfg")) == {
        ("exposed-service", "OUTSIDE-IN #3"), ("any-any", "SERVERS-IN #2"), ("shadowed", "SERVERS-IN #3"),
        ("shadowed", "SERVERS-IN #4"), ("redundant", "OUTSIDE-IN #4"), ("no-comment", "OUTSIDE-IN #3"),
        ("no-comment", "OUTSIDE-IN #4")}


def test_sample_junos():
    assert found(sample("dc-srx.cfg")) == {
        ("exposed-service", "untrust -> trust #2 'rdp-jump'"), ("exposed-service", "untrust -> trust #3 'partner-db'"),
        ("default-allow", "default-policy"), ("any-any", "trust -> untrust #1 'allow-out'"),
        ("redundant", "untrust -> trust #4 'web-in-copy'"), ("no-comment", "untrust -> trust #2 'rdp-jump'"),
        ("disabled", "untrust -> trust #5 'old-ftp'")}


def test_sample_iptables():
    assert found(sample("web-01.rules")) == {
        ("exposed-service", "INPUT #5"), ("all-ports-open", "INPUT #7"), ("default-allow", "INPUT"),
        ("redundant", "INPUT #6"), ("no-comment", "INPUT #5"), ("no-comment", "INPUT #6")}


def test_findings_are_sorted_by_severity():
    for name in ("branch-gw.rsc", "core-sw.cfg", "dc-srx.cfg", "web-01.rules"):
        ranks = [f.severity.rank for f in sample(name)]
        assert ranks == sorted(ranks, reverse=True)


# ---------- any-any ----------

def test_any_any_from_outside_is_high_and_inside_is_medium():
    cfg = ("interface Gi0/0\n description WAN\n ip access-group EDGE in\n"
           "ip access-list extended EDGE\n permit ip any any\nip access-list extended LAB\n permit ip any any\n")
    sev = {f.rule.ruleset: f.severity for f in run(cfg, "cisco_ios") if f.check == "any-any"}
    assert sev == {"EDGE": Severity.high, "LAB": Severity.medium}


def test_established_and_trusted_interface_rules_are_not_any_any():
    cfg = ("/ip firewall filter add action=accept chain=input connection-state=established,related comment=x\n"
           "/ip firewall filter add action=accept chain=input in-interface-list=LAN comment=x\n"
           "/ip firewall filter add action=drop chain=input\n")
    assert not [f for f in run(cfg, "mikrotik_routeros") if f.check == "any-any"]


# ---------- exposed services ----------

@pytest.mark.parametrize("port, sev", [(23, Severity.high), (22, Severity.medium), (3389, Severity.high), (6379, Severity.high)])
def test_exposed_service_severity(port, sev):
    cfg = f"*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport {port} -m comment --comment x -j ACCEPT\nCOMMIT\n"
    f = [f for f in run(cfg, "iptables") if f.check == "exposed-service"]
    assert len(f) == 1 and f[0].severity == sev


def test_restricted_source_is_not_exposed():
    cfg = "*filter\n:INPUT DROP [0:0]\n-A INPUT -s 10.0.0.0/8 -p tcp --dport 3389 -m comment --comment x -j ACCEPT\nCOMMIT\n"
    assert run(cfg, "iptables") == []


def test_port_range_containing_rdp_is_caught():
    cfg = "/ip firewall filter add action=accept chain=forward dst-port=3000-4000 protocol=tcp comment=x\n"
    assert any(f.check == "exposed-service" and "RDP" in f.detail for f in run(cfg, "mikrotik_routeros"))


def test_web_on_a_server_is_fine_but_webfig_on_a_router_is_not():
    srv = "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m multiport --dports 80,443 -m comment --comment web -j ACCEPT\nCOMMIT\n"
    assert run(srv, "iptables") == []
    rtr = ("/ip firewall filter add action=accept chain=input dst-port=80 protocol=tcp comment=x\n"
           "/ip firewall filter add action=drop chain=input\n/ip firewall filter add action=drop chain=forward\n")
    assert [f.check for f in run(rtr, "mikrotik_routeros")] == ["exposed-service"]


def test_from_lan_interface_list_is_not_internet():
    cfg = ("/ip firewall filter add action=accept chain=input dst-port=22 in-interface-list=LAN protocol=tcp comment=x\n"
           "/ip firewall filter add action=drop chain=input\n/ip firewall filter add action=drop chain=forward\n")
    assert run(cfg, "mikrotik_routeros") == []


# ---------- default allow ----------

def test_mikrotik_defconf_style_forward_drop_counts_as_final_drop():
    cfg = ("/ip firewall filter add action=drop chain=input in-interface-list=!LAN\n"
           "/ip firewall filter add action=drop chain=forward connection-nat-state=!dstnat in-interface-list=WAN\n")
    assert not [f for f in run(cfg, "mikrotik_routeros") if f.check == "default-allow"]


def test_drop_invalid_is_not_a_final_drop():
    cfg = ("/ip firewall filter add action=drop chain=input connection-state=invalid\n"
           "/ip firewall filter add action=drop chain=forward\n")
    assert [f.ruleset for f in run(cfg, "mikrotik_routeros") if f.check == "default-allow"] == ["input"]


def test_iptables_policy_drop_is_fine_and_final_drop_rule_is_fine():
    assert run("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\nCOMMIT\n", "iptables") == []
    assert run("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n-A INPUT -j DROP\nCOMMIT\n", "iptables") == []


# ---------- shadowed and redundant ----------

def test_conflicting_shadow():
    cfg = ("*filter\n:INPUT DROP [0:0]\n-A INPUT -s 10.0.0.0/8 -m comment --comment a -j DROP\n"
           "-A INPUT -s 10.1.2.0/24 -p tcp --dport 22 -m comment --comment b -j ACCEPT\nCOMMIT\n")
    f = [f for f in run(cfg, "iptables") if f.check == "shadowed"]
    assert len(f) == 1 and f[0].rule.position == 2 and f[0].related.position == 1


def test_partial_overlap_is_not_shadowed():
    cfg = ("*filter\n:INPUT DROP [0:0]\n-A INPUT -s 10.1.2.0/24 -p tcp --dport 22 -m comment --comment a -j ACCEPT\n"
           "-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -m comment --comment b -j ACCEPT\nCOMMIT\n")
    assert run(cfg, "iptables") == []


def test_rate_limited_rule_cannot_shadow():
    cfg = ("*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -m limit --limit 5/min -m comment --comment a -j DROP\n"
           "-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -m comment --comment b -j ACCEPT\nCOMMIT\n")
    assert not [f for f in run(cfg, "iptables") if f.check in ("shadowed", "redundant")]


def test_disabled_rule_does_not_shadow():
    cfg = ("/ip firewall filter add action=drop chain=forward disabled=yes\n"
           "/ip firewall filter add action=accept chain=forward src-address=10.0.0.0/8 comment=x\n")
    assert not [f for f in run(cfg, "mikrotik_routeros") if f.check == "shadowed"]


# ---------- comments ----------

def test_cisco_remark_counts_as_comment():
    cfg = "ip access-list extended A\n remark web\n permit tcp any host 192.0.2.1 eq 443\n"
    assert not [f for f in run(cfg, "cisco_ios") if f.check == "no-comment"]


def test_deny_rules_do_not_need_comments():
    assert not [f for f in run("ip access-list extended A\n deny ip any any\n", "cisco_ios") if f.check == "no-comment"]


# ---------- detection ----------

@pytest.mark.parametrize("name, vendor", [("branch-gw.rsc", "mikrotik_routeros"), ("core-sw.cfg", "cisco_ios"),
                                          ("dc-srx.cfg", "juniper_junos"), ("web-01.rules", "iptables")])
def test_vendor_detection(name, vendor):
    assert detect((SAMPLES / name).read_text()) == vendor


def test_unknown_vendor_is_a_clear_error():
    with pytest.raises(ValueError, match="--vendor"):
        parse("x", "hello world")
