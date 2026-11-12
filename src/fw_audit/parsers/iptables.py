"""Linux iptables, from `iptables-save` (filter table)."""

from __future__ import annotations

import re
import shlex

from ..model import Addr, Device, Rule
from .common import addr_list, port_list

_INTERNAL_IFACE = re.compile(r"^(lo|docker|br-|virbr|veth|cni|flannel|cali|wg|tun|tap)", re.I)
MODELED = {"-A", "-p", "-s", "-d", "-i", "-j", "-m", "--dport", "--dports", "--destination-port", "--ctstate", "--state",
           "--comment", "--src-range", "--match-set"}
ACTIONS = {"ACCEPT": "allow", "DROP": "deny", "REJECT": "deny"}


def parse(name: str, text: str) -> Device:
    dev = Device(name, "iptables")
    table = None
    pos: dict[str, int] = {}
    for no, raw in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        line = raw.strip()
        if line.startswith("*"):
            table = line[1:]
            continue
        if table != "filter" or not line or line.startswith("#"):
            continue
        if line.startswith(":"):
            chain, policy = line[1:].split()[:2]
            rs = dev.ruleset(chain)
            rs.default_action = ACTIONS.get(policy) if policy != "-" else None
            rs.applies_to_router = chain == "INPUT"
            continue
        if not line.startswith("-A "):
            continue
        try:
            t = shlex.split(line)
        except ValueError:
            t = line.split()
        f: dict[str, str] = {}
        negated: set[str] = set()
        i = 0
        while i < len(t):
            tok = t[i]
            if tok == "!" and i + 1 < len(t):
                negated.add(t[i + 1])
                i += 1
                continue
            if tok.startswith("-") and i + 1 < len(t) and not t[i + 1].startswith("-"):
                f.setdefault(tok, t[i + 1])
                i += 2
            else:
                i += 1
        chain = f.get("-A", "?")
        pos[chain] = pos.get(chain, 0) + 1
        target = f.get("-j", "")
        src = addr_list(f.get("-s")) if "-s" not in negated else Addr.of(names=(f"!{f.get('-s')}",))
        dst = addr_list(f.get("-d")) if "-d" not in negated else Addr.of(names=(f"!{f.get('-d')}",))
        if "--src-range" in f:
            src = addr_list(f["--src-range"])
        if "--match-set" in f:
            src = Addr.of(src.nets, src.names + (f"ipset:{f['--match-set']}",))
        dports = port_list(f.get("--dport") or f.get("--dports") or f.get("--destination-port") or "")
        iface = f.get("-i")
        state = f.get("--ctstate") or f.get("--state") or ""
        dev.rules.append(Rule(
            vendor=dev.vendor, ruleset=chain, position=pos[chain], action=ACTIONS.get(target, "other"),
            raw=line, line_no=no, protocol=f.get("-p") if f.get("-p") not in (None, "all") else None,
            src=src, dst=dst, dst_ports=dports, in_iface=iface,
            from_untrusted=chain in ("INPUT", "FORWARD") and src.any and not (iface and _INTERNAL_IFACE.match(iface))
            and "-i" not in negated,
            established_only=bool(state) and "NEW" not in state.upper().split(","),
            comment=f.get("--comment") or ("loopback" if iface == "lo" else None), logs=target == "LOG",
            narrowed=bool(set(f) - MODELED) or bool(negated) or iface == "lo" or bool(state and "NEW" not in state.upper()),
            extra=tuple(sorted(set(f) - MODELED)),
            state=state,
        ))
    if not dev.rules and not dev.rulesets:
        dev.notes.append("No filter table found. Use the output of iptables-save.")
    return dev
