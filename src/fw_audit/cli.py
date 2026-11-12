"""Command line.

    fw-audit scan edge-rtr.rsc core-sw.cfg dc-fw.cfg      # vendor detected from the file
    fw-audit scan server.rules --vendor iptables --fail-on high
    fw-audit demo                                         # bundled sample configs
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .checks import CHECKS, audit
from .model import Severity
from .parsers import PARSERS, parse
from .report import DeviceAudit, html_report, markdown, to_csv, to_json
from .summary import summarise


def _llm_settings() -> dict | None:
    base = os.getenv("LLM_BASE_URL")
    if not base:
        return None
    return {"base_url": base, "api_key": os.getenv("LLM_API_KEY", ""), "model": os.getenv("LLM_MODEL", "llama3.1:8b"),
            "mask": os.getenv("MASK_INTERNAL_IPS", "true").lower() != "false"}


def run_files(files: list[Path], vendor: str | None, ignore: set[str], llm: dict | None) -> list[DeviceAudit]:
    audits = []
    for p in files:
        dev = parse(p.stem, p.read_text(encoding="utf-8", errors="replace"), vendor)
        findings = [f for f in audit(dev) if f.check not in ignore]
        headline, actions, source = summarise(dev.name, findings, llm)
        audits.append(DeviceAudit(dev, findings, headline, actions, source, sorted(ignore)))
    return audits


def write(audits: list[DeviceAudit], out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    (out / "fw-audit.md").write_text(markdown(audits), encoding="utf-8")
    (out / "fw-audit.json").write_text(to_json(audits), encoding="utf-8")
    (out / "fw-audit.csv").write_text(to_csv(audits), encoding="utf-8")
    (out / "fw-audit.html").write_text(html_report(audits), encoding="utf-8")
    return out / "fw-audit.html"


def _print(audits: list[DeviceAudit]) -> None:
    for a in audits:
        c = a.counts
        print(f"  {a.device.name:<16} {a.device.vendor:<18} {len(a.device.rules):>3} rules   "
              f"high {c['high']:>2}  medium {c['medium']:>2}  low {c['low']:>2}  info {c['info']:>2}")


def cmd_scan(a: argparse.Namespace) -> int:
    ignore = set(filter(None, (a.ignore or "").split(",")))
    unknown = ignore - set(CHECKS)
    if unknown:
        print(f"Unknown check(s): {', '.join(sorted(unknown))}. Known: {', '.join(CHECKS)}", file=sys.stderr)
        return 1
    try:
        audits = run_files([Path(f) for f in a.files], a.vendor, ignore, _llm_settings())
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    _print(audits)
    print(f"\nReport: {write(audits, Path(a.out))}")
    if a.fail_on and any(f.severity.rank >= Severity(a.fail_on).rank for x in audits for f in x.findings):
        return 2
    return 0


def cmd_demo(a: argparse.Namespace) -> int:
    folder = Path(__file__).resolve().parents[2] / "samples" / "configs"
    if not folder.exists():
        print("samples/ not found; run the demo from a clone of the repository.", file=sys.stderr)
        return 1
    audits = run_files(sorted(folder.iterdir()), None, set(), _llm_settings())
    _print(audits)
    print(f"\nReport: {write(audits, Path(a.out))}")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="fw-audit", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Audit one or more firewall config files")
    s.add_argument("files", nargs="+")
    s.add_argument("--vendor", choices=list(PARSERS), help="Skip auto-detection")
    s.add_argument("--out", default="reports")
    s.add_argument("--ignore", help=f"Comma-separated checks to skip: {', '.join(CHECKS)}")
    s.add_argument("--fail-on", choices=[x.value for x in Severity], help="Exit with code 2 if a finding reaches this severity")
    s.set_defaults(func=cmd_scan)
    d = sub.add_parser("demo", help="Audit the bundled sample configs")
    d.add_argument("--out", default="reports")
    d.set_defaults(func=cmd_demo)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
