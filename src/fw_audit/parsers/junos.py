"""Juniper SRX security policies from `show configuration | display set`.

Address-book entries and custom applications are resolved, so a policy
that names "web-01" or "my-rdp" is checked against the real address and port.
"""

from __future__ import annotations

import ipaddress
import re
import shlex

from ..model import Addr, Device, Ports, Rule
from .common import JUNOS_APPS, UNTRUSTED_NAME, port_list

_POLICY = re.compile(r"^(deactivate|set) security policies (?:from-zone (\S+) to-zone (\S+)|global) policy (\S+)(?: (.*))?$")


def _split(rest: str) -> list[str]:
    try:
        return shlex.split(rest)
    except ValueError:
        return rest.split()


def parse(name: str, text: str) -> Device:
    dev = Device(name, "juniper_junos")
    lines = text.replace("\r\n", "\n").split("\n")
    book: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
    sets: dict[str, list[str]] = {}
    apps: dict[str, tuple[str | None, Ports]] = {}
    for line in lines:
        t = _split(line.strip())
        if t[:4] == ["set", "security", "address-book", "global"] and len(t) >= 7 and t[4] == "address":
            try:
                book.setdefault(t[5], []).append(ipaddress.ip_network(t[6], strict=False))
            except ValueError:
                pass
        elif t[:4] == ["set", "security", "address-book", "global"] and len(t) >= 8 and t[4] == "address-set":
            sets.setdefault(t[5], []).append(t[7])
        elif t[:3] == ["set", "applications", "application"] and len(t) >= 6:
            proto, ports = apps.get(t[3], (None, Ports.anyport()))
            if t[4] == "protocol":
                proto = t[5]
            elif t[4] == "destination-port":
                ports = port_list(t[5])
            apps[t[3]] = (proto, ports)
        elif line.strip() == "set security policies default-policy permit-all":
            for rs in dev.rulesets.values():
                rs.default_action = "allow"
            dev.notes.append("default-policy permit-all")

    def resolve(names: list[str]) -> Addr:
        if not names or "any" in names or "any-ipv4" in names:
            return Addr.anywhere()
        nets, unresolved = [], []
        for n in names:
            members = sets.get(n, [n])
            for m in members:
                if m in book:
                    nets += book[m]
                else:
                    unresolved.append(m)
        return Addr.of(nets, unresolved)

    order: list[tuple[str, str]] = []
    policies: dict[tuple[str, str], dict] = {}
    for no, line in enumerate(lines, 1):
        m = _POLICY.match(line.strip())
        if not m:
            continue
        verb, frm, to, pol, rest = m.groups()
        zone = f"{frm or 'global'} -> {to or 'global'}"
        key = (zone, pol)
        if key not in policies:
            order.append(key)
            policies[key] = {"src": [], "dst": [], "app": [], "action": None, "line": no, "desc": None, "log": False,
                             "disabled": False, "from": frm, "raw": []}
        p = policies[key]
        p["raw"].append(line.strip())
        if verb == "deactivate":
            p["disabled"] = True
            continue
        t = _split(rest or "")
        if t[:2] == ["match", "source-address"] and len(t) > 2:
            p["src"].append(t[2])
        elif t[:2] == ["match", "destination-address"] and len(t) > 2:
            p["dst"].append(t[2])
        elif t[:2] == ["match", "application"] and len(t) > 2:
            p["app"].append(t[2])
        elif t[:2] == ["match", "from-zone"] and len(t) > 2:
            p["from"] = t[2]
        elif t[:1] == ["then"] and len(t) > 1:
            if t[1] in ("permit", "deny", "reject"):
                p["action"] = "allow" if t[1] == "permit" else "deny"
            elif t[1] == "log":
                p["log"] = True
        elif t[:1] == ["description"]:
            p["desc"] = " ".join(t[1:])

    pos: dict[str, int] = {}
    for zone, pol in order:
        p = policies[(zone, pol)]
        dev.ruleset(zone)
        pos[zone] = pos.get(zone, 0) + 1
        proto, ranges, unknown = None, [], False
        app_any = not p["app"] or "any" in p["app"]
        if not app_any:
            protos = set()
            for a in p["app"]:
                if a in JUNOS_APPS:
                    pr, port = JUNOS_APPS[a]
                    protos.add(pr)
                    if port:
                        ranges.append((port, port))
                elif a in apps:
                    pr, pt = apps[a]
                    protos.add(pr)
                    ranges += pt.ranges
                    unknown = unknown or pt.unknown or pt.any
                else:
                    unknown = True
            proto = protos.pop() if len(protos) == 1 else None
        ports = Ports.anyport() if app_any else Ports(False, tuple(sorted(set(ranges))), unknown)
        if not app_any and not ranges and proto == "icmp":
            ports = Ports.anyport()
        dev.rules.append(Rule(
            vendor=dev.vendor, ruleset=zone, position=pos[zone], action=p["action"] or "other",
            raw=" / ".join(p["raw"][:6]) + (" ..." if len(p["raw"]) > 6 else ""), line_no=p["line"],
            protocol=proto, src=resolve(p["src"]), dst=resolve(p["dst"]), dst_ports=ports,
            in_iface=p["from"], from_untrusted=bool(p["from"] and UNTRUSTED_NAME.search(p["from"])),
            comment=p["desc"], disabled=p["disabled"], logs=p["log"], name=pol,
        ))
    if any("permit-all" in n for n in dev.notes):
        for rs in dev.rulesets.values():
            rs.default_action = "allow"
    if not dev.rules:
        dev.notes.append("No security policies found.")
    return dev
