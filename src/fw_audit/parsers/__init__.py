from __future__ import annotations

from ..model import Device
from . import cisco, iptables, junos, mikrotik

PARSERS = {
    "mikrotik_routeros": mikrotik.parse,
    "cisco_ios": cisco.parse,
    "juniper_junos": junos.parse,
    "iptables": iptables.parse,
}


def detect(text: str) -> str | None:
    """Guess the vendor from the config text."""
    head = text[:20000]
    if "/ip firewall filter" in head or "by RouterOS" in head:
        return "mikrotik_routeros"
    if "set security policies" in head or "## Last commit" in head:
        return "juniper_junos"
    if "*filter" in head and ":INPUT" in head:
        return "iptables"
    if "ip access-list" in head or "\naccess-list " in head or head.startswith("access-list "):
        return "cisco_ios"
    return None


def parse(name: str, text: str, vendor: str | None = None) -> Device:
    vendor = vendor or detect(text)
    if vendor not in PARSERS:
        raise ValueError(f"{name}: could not tell the vendor; pass --vendor ({', '.join(PARSERS)})")
    return PARSERS[vendor](name, text)
