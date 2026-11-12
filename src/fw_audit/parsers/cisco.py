"""Cisco IOS / IOS-XE access lists: named (standard and extended) and numbered.

An ACL is treated as facing the internet when its name, or the description
or name of an interface it is applied to inbound, looks like an outside
interface (outside, wan, internet, isp...).
"""

from __future__ import annotations

import ipaddress
import re

from ..model import Addr, Device, Ports, Rule
from .common import SERVICE_PORTS, UNTRUSTED_NAME, port_list

_NAMED = re.compile(r"^ip access-list (standard|extended) (\S+)")
_NUMBERED = re.compile(r"^access-list (\d+) (.*)$")
_ENTRY = re.compile(r"^(?:(\d+)\s+)?(permit|deny|remark)\s*(.*)$")


def _addr(tokens: list[str]) -> Addr:
    if not tokens:
        return Addr.anywhere()
    t = tokens.pop(0)
    if t == "any":
        return Addr.anywhere()
    if t == "host" and tokens:
        return Addr.of([ipaddress.ip_network(tokens.pop(0))])
    if t in ("object-group", "addrgroup") and tokens:
        return Addr.of(names=(f"group:{tokens.pop(0)}",))
    if tokens and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[0]):
        wildcard = tokens.pop(0)
        try:
            return Addr.of([ipaddress.ip_network(f"{t}/{wildcard}", strict=False)])
        except ValueError:  # non-contiguous wildcard
            return Addr.of(names=(f"{t} {wildcard}",))
    try:
        return Addr.of([ipaddress.ip_network(t)])  # standard ACL single host
    except ValueError:
        return Addr.of(names=(t,))


def _ports(tokens: list[str]) -> Ports:
    if not tokens or tokens[0] not in ("eq", "range", "gt", "lt", "neq"):
        return Ports.anyport()
    op = tokens.pop(0)

    def num(t: str) -> int | None:
        return int(t) if t.isdigit() else SERVICE_PORTS.get(t)

    if op == "range" and len(tokens) >= 2:
        lo, hi = num(tokens.pop(0)), num(tokens.pop(0))
        return Ports.of([(lo, hi)]) if lo is not None and hi is not None else Ports(False, (), True)
    if op in ("gt", "lt") and tokens:
        n = num(tokens.pop(0))
        if n is None:
            return Ports(False, (), True)
        return Ports.of([(n + 1, 65535)] if op == "gt" else [(1, n - 1)])
    if op == "neq":
        n = num(tokens.pop(0)) if tokens else None
        return Ports.of([(1, n - 1), (n + 1, 65535)]) if n else Ports(False, (), True)
    vals = []
    while tokens and tokens[0] not in ("log", "log-input", "established", "any", "host", "object-group") \
            and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[0]):
        vals.append(tokens.pop(0))
    return port_list(",".join(vals))


def _parse_entry(dev: Device, acl: str, kind: str, body: str, no: int, pos: int, comment: str | None,
                 untrusted: set[str]) -> Rule | None:
    m = _ENTRY.match(body.strip())
    if not m or m.group(2) == "remark":
        return None
    action, rest = m.group(2), m.group(3)
    tokens = rest.split()
    proto = None
    if kind == "extended":
        proto = tokens.pop(0) if tokens else "ip"
        proto = None if proto in ("ip", "ipv4") else proto
    src = _addr(tokens)
    narrowed = False
    if kind == "extended":
        sports = _ports(tokens)  # source ports: not checked, but they make the entry narrower
        narrowed = not sports.any
        dst = _addr(tokens)
        dports = _ports(tokens) if proto in ("tcp", "udp", None) else Ports.anyport()
    else:
        dst, dports = Addr.anywhere(), Ports.anyport()
    return Rule(
        vendor=dev.vendor, ruleset=acl, position=pos, action="allow" if action == "permit" else "deny",
        raw=body.strip(), line_no=no, protocol=proto, src=src, dst=dst, dst_ports=dports,
        from_untrusted=acl in untrusted, established_only="established" in tokens,
        comment=comment, logs="log" in tokens or "log-input" in tokens,
        narrowed=narrowed or any(t in tokens for t in ("established", "fragments", "time-range", "dscp", "precedence", "ack", "syn")),
    )


def _untrusted_acls(lines: list[str]) -> set[str]:
    out: set[str] = set()
    iface, desc = None, ""
    for line in lines:
        if line.startswith("interface "):
            iface, desc = line.split(None, 1)[1], ""
        elif line.startswith(" description ") and iface:
            desc = line.strip()[len("description "):]
        elif iface and re.match(r"^ ip access-group (\S+) in", line):
            acl = line.split()[2]
            if UNTRUSTED_NAME.search(desc) or UNTRUSTED_NAME.search(iface):
                out.add(acl)
        elif not line.startswith(" "):
            iface = None
    for line in lines:
        m = _NAMED.match(line) or _NUMBERED.match(line)
        if m:
            name = m.group(2) if line.startswith("ip ") else m.group(1)
            if UNTRUSTED_NAME.search(name):
                out.add(name)
    return out


def parse(name: str, text: str) -> Device:
    dev = Device(name, "cisco_ios")
    lines = text.replace("\r\n", "\n").split("\n")
    untrusted = _untrusted_acls(lines)
    pos: dict[str, int] = {}
    acl, kind, remark = None, None, None
    for no, line in enumerate(lines, 1):
        m = _NAMED.match(line)
        if m:
            kind, acl, remark = m.group(1), m.group(2), None
            dev.ruleset(acl)
            continue
        if acl and line.startswith(" "):
            body = line.strip()
            if body.startswith("remark"):
                remark = body[len("remark"):].strip()
                continue
            pos[acl] = pos.get(acl, 0) + 1
            r = _parse_entry(dev, acl, kind, body, no, pos[acl], remark, untrusted)
            if r:
                dev.rules.append(r)
            remark = None
            continue
        acl = None
        m = _NUMBERED.match(line)
        if m:
            num, body = m.group(1), m.group(2)
            dev.ruleset(num)
            if body.startswith("remark"):
                remark = body[len("remark"):].strip()
                continue
            k = "standard" if int(num) < 100 or 1300 <= int(num) <= 1999 else "extended"
            pos[num] = pos.get(num, 0) + 1
            r = _parse_entry(dev, num, k, body, no, pos[num], remark, untrusted)
            if r:
                dev.rules.append(r)
            remark = None
    if not dev.rules:
        dev.notes.append("No access-list entries found.")
    return dev
