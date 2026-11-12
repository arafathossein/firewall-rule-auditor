from __future__ import annotations

import ipaddress
import re
import shlex

from ..model import Addr, Ports

# Names used in Cisco ACLs, iptables and service files.
SERVICE_PORTS = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53, "www": 80, "http": 80,
    "pop3": 110, "ntp": 123, "netbios-ssn": 139, "imap": 143, "snmp": 161, "snmptrap": 162, "bgp": 179, "ldap": 389,
    "https": 443, "smb": 445, "microsoft-ds": 445, "syslog": 514, "ldaps": 636, "imaps": 993, "pop3s": 995,
    "ms-sql-s": 1433, "mssql": 1433, "pptp": 1723, "mysql": 3306, "rdp": 3389, "ms-wbt-server": 3389,
    "postgresql": 5432, "vnc": 5900, "winbox": 8291, "isakmp": 500, "tftp": 69,
}

# Predefined Junos applications
JUNOS_APPS = {
    "junos-ftp": ("tcp", 21), "junos-ssh": ("tcp", 22), "junos-telnet": ("tcp", 23), "junos-smtp": ("tcp", 25),
    "junos-dns-udp": ("udp", 53), "junos-dns-tcp": ("tcp", 53), "junos-http": ("tcp", 80), "junos-https": ("tcp", 443),
    "junos-pop3": ("tcp", 110), "junos-ntp": ("udp", 123), "junos-imap": ("tcp", 143), "junos-snmp-agentx": ("tcp", 705),
    "junos-ldap": ("tcp", 389), "junos-smb": ("tcp", 445), "junos-ms-sql": ("tcp", 1433), "junos-mysql": ("tcp", 3306),
    "junos-rdp": ("tcp", 3389), "junos-ms-rdp": ("tcp", 3389), "junos-vnc": ("tcp", 5900), "junos-pgsql": ("tcp", 5432),
    "junos-ping": ("icmp", None), "junos-icmp-all": ("icmp", None),
}

UNTRUSTED_NAME = re.compile(r"(^|[-_ ])(wan|outside|internet|untrust(ed)?|public|isp|external|ext|uplink-isp|dmz-in)([-_ 0-9]|$)", re.I)


def kv(line: str) -> dict[str, str]:
    """Parse MikroTik-style key=value pairs, honouring quotes."""
    out = {}
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        tokens = line.split()
    for t in tokens:
        if "=" in t:
            k, v = t.split("=", 1)
            out[k] = v
    return out


def port_list(spec: str) -> Ports:
    """'22', '80,443', '8000-8100', 'ssh', '!22' -> Ports"""
    spec = spec.strip()
    if not spec or spec == "any":
        return Ports.anyport()
    if spec.startswith("!"):
        return Ports(False, (), True)
    ranges, unknown = [], False
    for part in re.split(r"[,\s]+", spec):
        if not part:
            continue
        part = part.replace(":", "-")
        m = re.fullmatch(r"(\d+)-(\d+)", part)
        if m:
            ranges.append((int(m.group(1)), int(m.group(2))))
        elif part.isdigit():
            ranges.append((int(part), int(part)))
        elif part.lower() in SERVICE_PORTS:
            p = SERVICE_PORTS[part.lower()]
            ranges.append((p, p))
        else:
            unknown = True
    p = Ports.of(ranges)
    return Ports(False, p.ranges, unknown) if unknown else p


def net(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def addr_list(spec: str | None) -> Addr:
    """'10.0.0.0/8', '10.0.0.1-10.0.0.9', '!10.0.0.0/8', '' -> Addr"""
    if not spec:
        return Addr.anywhere()
    if spec.startswith("!"):
        return Addr.of(names=(spec,))
    nets, names = [], []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part and "/" not in part:
            lo, _, hi = part.partition("-")
            try:
                nets += list(ipaddress.summarize_address_range(ipaddress.ip_address(lo), ipaddress.ip_address(hi)))
                continue
            except ValueError:
                pass
        n = net(part)
        if n is None:
            names.append(part)
        else:
            nets.append(n)
    return Addr.of(nets, names)
