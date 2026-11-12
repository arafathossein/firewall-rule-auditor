"""The audit checks. Each returns findings with a reason and a concrete fix."""

from __future__ import annotations

from .model import Device, Finding, Rule, Ruleset, Severity

H, M, L, I = Severity.high, Severity.medium, Severity.low, Severity.info

# Services that should never be reachable from the whole internet.
SENSITIVE: dict[int, tuple[str, Severity]] = {
    21: ("FTP", H), 22: ("SSH", M), 23: ("Telnet", H), 135: ("MS RPC", H), 139: ("NetBIOS", H), 161: ("SNMP", H),
    445: ("SMB", H), 1433: ("SQL Server", H), 2375: ("Docker API", H), 3306: ("MySQL", H), 3389: ("RDP", H),
    5432: ("PostgreSQL", H), 5900: ("VNC", H), 5985: ("WinRM", H), 5986: ("WinRM", H), 6379: ("Redis", H),
    8291: ("Winbox", H), 8728: ("RouterOS API", H), 8729: ("RouterOS API-SSL", M), 9200: ("Elasticsearch", H),
    11211: ("Memcached", H), 27017: ("MongoDB", H),
}
# On a router's own input chain, web admin is sensitive too.
DEVICE_ADMIN = {80: ("web admin (HTTP)", H), 443: ("web admin (HTTPS)", M)}

CHECKS = ["any-any", "exposed-service", "all-ports-open", "default-allow", "shadowed", "redundant", "no-comment", "disabled"]


def _live(r: Rule) -> bool:
    return not r.disabled and r.action in ("allow", "deny")


def _is_any_any(r: Rule) -> bool:
    # A rule limited to a trusted interface or zone ("from LAN") is not any-to-any.
    by_iface = r.in_iface is not None and not r.from_untrusted
    return (r.src.any and r.dst.any and r.dst_ports.any and r.protocol is None and not r.established_only
            and not r.narrowed and (not by_iface or r.vendor == "juniper_junos"))


def any_any(dev: Device) -> list[Finding]:
    out = []
    for r in dev.rules:
        if _live(r) and r.action == "allow" and _is_any_any(r):
            sev = H if r.from_untrusted else M
            where = "from the internet side" if r.from_untrusted else "between the networks this rule sits on"
            out.append(Finding("any-any", sev, "Allows any source to any destination on any port",
                               f"{r.label} permits all traffic {where}. Every rule after it in {r.ruleset} has no effect for allowed traffic.",
                               "Replace it with rules for the specific sources, destinations and ports that are needed, then remove it.",
                               rule=r))
    return out


def exposed_services(dev: Device) -> list[Finding]:
    out = []
    for r in dev.rules:
        if not (_live(r) and r.action == "allow" and r.open_to_internet and not r.established_only):
            continue
        if _is_any_any(r) or r.protocol not in (None, "tcp", "udp", "6", "17"):
            continue
        if r.dst_ports.any:
            if r.protocol in ("tcp", "udp", "6", "17") or not r.dst.any:
                proto = (r.protocol or "all").upper()
                out.append(Finding("all-ports-open", H, f"Every {proto} port open to the internet",
                                   f"{r.label} accepts {proto} on all ports from any source to {r.dst}.",
                                   "List only the ports the service needs, or restrict the source.", rule=r))
            continue
        table = dict(SENSITIVE)
        if dev.vendor == "mikrotik_routeros" and dev.rulesets.get(r.ruleset, Ruleset(r.ruleset)).applies_to_router:
            table.update(DEVICE_ADMIN)  # on a server, 80/443 on INPUT is the service itself
        hits = [(p, *table[p]) for p in sorted(table) if r.dst_ports.contains(p)]
        if not hits:
            continue
        sev = max((s for _, _, s in hits), key=lambda s: s.rank)
        names = ", ".join(f"{n} ({p})" for p, n, _ in hits)
        out.append(Finding("exposed-service", sev, f"{hits[0][1]} open to the internet" if len(hits) == 1 else
                           "Admin or database services open to the internet",
                           f"{r.label} lets any source reach {names} on {r.dst}.",
                           "Allow only your management network or a VPN, for example a source address list, "
                           "and use a jump host or VPN for remote access.", rule=r))
    return out


def _catch_all_deny(rules: list[Rule]) -> bool:
    """A deny that catches everything still left, or at least everything arriving from the untrusted side.

    MikroTik's default "drop everything from WAN that wasn't port-forwarded"
    (connection-nat-state=!dstnat) counts too.
    """
    for r in rules:
        if not (_live(r) and r.action == "deny" and r.src.any and r.dst.any and r.dst_ports.any and r.protocol is None):
            continue
        if r.state or set(r.extra) - {"connection-nat-state"}:
            continue
        if r.in_iface is None or r.from_untrusted:
            return True
    return False


def default_allow(dev: Device) -> list[Finding]:
    out = []
    by_set: dict[str, list[Rule]] = {}
    for r in dev.rules:
        by_set.setdefault(r.ruleset, []).append(r)
    if dev.vendor == "mikrotik_routeros":
        for chain, sev in (("input", H), ("forward", M)):
            if not _catch_all_deny(by_set.get(chain, [])):
                what = "the router itself" if chain == "input" else "networks behind the router"
                out.append(Finding("default-allow", sev, f"No final drop rule in the {chain} chain",
                                   f"RouterOS accepts anything a chain does not drop. Traffic to {what} that no rule matches is allowed.",
                                   f"End the {chain} chain with a drop rule for everything not accepted above it "
                                   "(at minimum for traffic arriving on the WAN interface list).", ruleset=chain))
    elif dev.vendor == "iptables":
        for chain, sev in (("INPUT", H), ("FORWARD", M)):
            rs = dev.rulesets.get(chain)
            if rs and rs.default_action == "allow" and not _catch_all_deny(by_set.get(chain, [])):
                out.append(Finding("default-allow", sev, f"{chain} policy is ACCEPT with no final DROP",
                                   f"Packets that match no rule in {chain} are accepted.",
                                   f"Set the policy with iptables -P {chain} DROP after allowing what you need, "
                                   "or add a final DROP rule.", ruleset=chain))
    elif dev.vendor == "juniper_junos" and any("permit-all" in n for n in dev.notes):
        out.append(Finding("default-allow", H, "Default policy permits all traffic",
                           "set security policies default-policy permit-all lets through any traffic no policy matches, "
                           "between every pair of zones.",
                           "Change it to deny-all (the Junos default) and add policies for what is needed.", ruleset="default-policy"))
    return out


def _covers(e: Rule, r: Rule) -> bool:
    if e.narrowed or (e.established_only and not r.established_only):
        return False
    if e.protocol is not None and e.protocol != r.protocol:
        return False
    if e.in_iface is not None and e.in_iface != r.in_iface:
        return False
    if not (e.src.covers(r.src) and e.dst.covers(r.dst)):
        return False
    if r.protocol in ("tcp", "udp", "6", "17") or (r.protocol is None and not r.dst_ports.any):
        return e.dst_ports.covers(r.dst_ports)
    return e.dst_ports.any


def shadowed(dev: Device) -> list[Finding]:
    out = []
    by_set: dict[str, list[Rule]] = {}
    for r in dev.rules:
        if _live(r):
            by_set.setdefault(r.ruleset, []).append(r)
    for rules in by_set.values():
        for i, r in enumerate(rules):
            e = next((e for e in rules[:i] if _covers(e, r)), None)
            if e is None:
                continue
            if e.action != r.action:
                out.append(Finding("shadowed", M, "Rule never matches: an earlier rule decides first",
                                   f"{r.label} ({r.action}) is fully covered by {e.label} ({e.action}), so its {r.action} never happens.",
                                   "Move it above the earlier rule if it is still wanted, or delete it.", rule=r, related=e))
            else:
                out.append(Finding("redundant", L, "Redundant rule",
                                   f"{r.label} repeats what {e.label} already does.",
                                   "Delete it to keep the rule base readable.", rule=r, related=e))
    return out


def no_comment(dev: Device) -> list[Finding]:
    return [Finding("no-comment", L, "Allow rule without a comment",
                    f"{r.label} has no comment, so nobody can tell who needs it or whether it is still required.",
                    "Add a comment with the owner, the reason and a ticket number.", rule=r)
            for r in dev.rules if _live(r) and r.action == "allow" and not (r.comment or "").strip()
            and not r.established_only]


def disabled(dev: Device) -> list[Finding]:
    return [Finding("disabled", I, "Disabled rule left in place",
                    f"{r.label} is disabled. Old disabled rules get re-enabled by mistake.",
                    "Delete it if it is no longer needed; the config backup keeps a record.", rule=r)
            for r in dev.rules if r.disabled]


ALL = [any_any, exposed_services, default_allow, shadowed, no_comment, disabled]


def audit(dev: Device) -> list[Finding]:
    findings = [f for check in ALL for f in check(dev)]
    return sorted(findings, key=lambda f: (-f.severity.rank, CHECKS.index(f.check),
                                           f.rule.line_no if f.rule else 0))
