"""One rule model for every vendor, so every check is written once."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum

Net = ipaddress.IPv4Network | ipaddress.IPv6Network


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high"].index(self.value)


@dataclass(frozen=True)
class Addr:
    """A source or destination. any=True matches everything.

    nets are resolved prefixes; names are objects we could not resolve
    (address lists, object groups, negations). A rule with names is
    restricted, but we can't prove what it covers.
    """

    any: bool = True
    nets: tuple[Net, ...] = ()
    names: tuple[str, ...] = ()

    @classmethod
    def anywhere(cls) -> "Addr":
        return cls(True)

    @classmethod
    def of(cls, nets=(), names=()) -> "Addr":
        nets = tuple(nets)
        if any(n.prefixlen == 0 for n in nets):
            return cls(True)
        return cls(False, nets, tuple(names))

    def covers(self, other: "Addr") -> bool:
        if self.any:
            return True
        if other.any:
            return False
        if other.names and not set(other.names) <= set(self.names):
            return False
        return all(any(o.version == s.version and o.subnet_of(s) for s in self.nets) for o in other.nets)

    def __str__(self) -> str:
        if self.any:
            return "any"
        return ", ".join([str(n) for n in self.nets] + list(self.names))


PortRange = tuple[int, int]


@dataclass(frozen=True)
class Ports:
    """Destination ports. any=True when the rule does not limit ports."""

    any: bool = True
    ranges: tuple[PortRange, ...] = ()
    unknown: bool = False  # e.g. a named service we couldn't map

    @classmethod
    def anyport(cls) -> "Ports":
        return cls(True)

    @classmethod
    def of(cls, ranges) -> "Ports":
        return cls(False, tuple(sorted(set(ranges))))

    def contains(self, port: int) -> bool:
        return self.any or any(lo <= port <= hi for lo, hi in self.ranges)

    def covers(self, other: "Ports") -> bool:
        if self.any:
            return True
        if other.any or other.unknown or self.unknown:
            return False
        return all(any(lo <= olo and ohi <= hi for lo, hi in self.ranges) for olo, ohi in other.ranges)

    def __str__(self) -> str:
        if self.any:
            return "any"
        parts = [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in self.ranges]
        return ",".join(parts) + (" (+unresolved)" if self.unknown else "")


@dataclass
class Rule:
    vendor: str
    ruleset: str  # chain, ACL name or zone pair
    position: int  # 1-based order inside the ruleset
    action: str  # "allow", "deny" or "other" (jump, log, mark...)
    raw: str
    line_no: int
    protocol: str | None = None  # None means any
    src: Addr = field(default_factory=Addr.anywhere)
    dst: Addr = field(default_factory=Addr.anywhere)
    dst_ports: Ports = field(default_factory=Ports.anyport)
    in_iface: str | None = None  # None means any interface / zone
    from_untrusted: bool = False  # parser's view: can traffic from the internet reach this rule?
    established_only: bool = False  # matches only replies to existing connections
    narrowed: bool = False  # has conditions this tool doesn't model (rate limits, flags, source ports...)
    extra: tuple[str, ...] = ()  # names of those conditions
    state: str = ""  # connection-state / ctstate match, if any
    comment: str | None = None
    disabled: bool = False
    logs: bool = False
    name: str | None = None  # policy or rule name, where the vendor has one

    @property
    def label(self) -> str:
        n = f" '{self.name}'" if self.name else ""
        return f"{self.ruleset} #{self.position}{n}"

    @property
    def open_to_internet(self) -> bool:
        """Any source address, reachable from an untrusted side."""
        return self.src.any and self.from_untrusted


@dataclass
class Ruleset:
    name: str
    default_action: str | None = None  # "allow", "deny" or None when the vendor's default applies
    applies_to_router: bool = False  # MikroTik input chain, iptables INPUT: traffic to the device itself


@dataclass
class Device:
    name: str
    vendor: str
    rules: list[Rule] = field(default_factory=list)
    rulesets: dict[str, Ruleset] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def ruleset(self, name: str) -> Ruleset:
        return self.rulesets.setdefault(name, Ruleset(name))


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str
    fix: str
    rule: Rule | None = None
    related: Rule | None = None  # e.g. the rule that shadows this one
    ruleset: str | None = None
