"""MikroTik RouterOS: /ip firewall filter from `/export` (terse or block form)."""

from __future__ import annotations

import re

from ..model import Addr, Device, Rule
from .common import UNTRUSTED_NAME, addr_list, kv, port_list

MODELED = {"chain", "action", "protocol", "src-address", "dst-address", "src-address-list", "dst-address-list", "dst-port",
           "in-interface", "in-interface-list", "connection-state", "comment", "disabled", "log", "log-prefix", "place-before"}
ACTIONS = {"accept": "allow", "drop": "deny", "reject": "deny", "tarpit": "deny"}
LAN_LISTS = re.compile(r"^(lan|inside|trusted|mgmt|management)", re.I)
_MENU = re.compile(r"^/[a-z0-9][a-z0-9 -]*$")


def _lines(text: str):
    """Yield (line_no, full command) with block exports expanded to terse form."""
    menu, buf, start = "", "", 0
    for no, raw in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        line = raw.strip()
        if buf:
            line = buf + " " + line
            buf = ""
        else:
            start = no
        if line.endswith("\\"):
            buf = line[:-1].rstrip()
            continue
        if not line or line.startswith("#"):
            continue
        if _MENU.match(line):
            menu = line
            continue
        if not line.startswith("/") and menu:
            line = f"{menu} {line}"
        yield start, line


def _untrusted(f: dict[str, str]) -> bool:
    if f.get("src-address") or f.get("src-address-list"):
        return False
    lst, iface = f.get("in-interface-list", ""), f.get("in-interface", "")
    if lst:
        if lst.startswith("!"):  # "not LAN" means everything else, the WAN included
            return bool(LAN_LISTS.match(lst[1:]))
        return not LAN_LISTS.match(lst)
    if iface:
        if iface.startswith("!"):
            return True
        return bool(UNTRUSTED_NAME.search(iface) or re.match(r"^(ether1|pppoe|lte|sfp1)\b", iface, re.I))
    return True  # no interface limit: traffic from every interface, the internet included


def parse(name: str, text: str) -> Device:
    dev = Device(name, "mikrotik_routeros")
    pos: dict[str, int] = {}
    for no, line in _lines(text):
        if not line.startswith("/ip firewall filter add"):
            continue
        f = kv(line)
        chain = f.get("chain", "?")
        pos[chain] = pos.get(chain, 0) + 1
        rs = dev.ruleset(chain)
        rs.applies_to_router = chain == "input"
        src = addr_list(f.get("src-address"))
        if f.get("src-address-list"):
            src = Addr.of(src.nets, src.names + (f"list:{f['src-address-list']}",))
        dst = addr_list(f.get("dst-address"))
        if f.get("dst-address-list"):
            dst = Addr.of(dst.nets, dst.names + (f"list:{f['dst-address-list']}",))
        state = f.get("connection-state", "")
        dev.rules.append(Rule(
            vendor=dev.vendor, ruleset=chain, position=pos[chain],
            action=ACTIONS.get(f.get("action", "accept"), "other"),
            raw=line, line_no=no,
            protocol=f.get("protocol") or None,
            src=src, dst=dst,
            dst_ports=port_list(f.get("dst-port", "")),
            in_iface=f.get("in-interface-list") or f.get("in-interface") or None,
            from_untrusted=_untrusted(f) and chain in ("input", "forward"),
            established_only=bool(state) and not ({"new", "untracked"} & set(state.split(","))) and "invalid" not in state,
            comment=f.get("comment") or None,
            disabled=f.get("disabled") == "yes",
            logs=f.get("log") == "yes",
            narrowed=bool(set(f) - MODELED) or bool(state and "new" not in state.split(",")),
            extra=tuple(sorted(set(f) - MODELED)),
            state=state,
        ))
    if not dev.rules:
        dev.notes.append("No /ip firewall filter rules found. Was the export taken with /export (not /export compact of another menu)?")
    return dev
