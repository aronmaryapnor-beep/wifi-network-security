#!/usr/bin/env python3
"""Wi-Fi Network Security audit CLI.

Commands:
  audit       Score a router configuration (JSON) against the security baseline
  passphrase  Check passphrase strength (hidden input, never stored)
  local       Inspect the security of this computer's current Wi-Fi connection
  template    Print a blank configuration file to fill in from your router

Use only on networks you own or have written permission to assess.
"""

import argparse
import getpass
import json
import sys
from pathlib import Path

from wifi_audit import __version__
from wifi_audit.checks import audit
from wifi_audit.local_scan import current_connection
from wifi_audit.passphrase import evaluate
from wifi_audit.report import to_html, to_markdown

TEMPLATE = {
    "router_model": "Enter router brand and model",
    "firmware_version": "Enter version",
    "ssid": "Enter SSID",
    "assessor": "Your name",
    "security_mode": "WPA3-Personal | WPA2/WPA3-Personal | WPA2-Personal | WPA-Personal | WEP | Open",
    "encryption": "AES | TKIP | AES+TKIP",
    "passphrase_length": 0,
    "admin_default_credentials_changed": True,
    "admin_https": True,
    "wps_enabled": False,
    "remote_management": False,
    "upnp_enabled": False,
    "guest_network_enabled": True,
    "guest_isolation": True,
    "firmware_up_to_date": True,
    "pmf": "required | optional | disabled",
    "ssid_is_default": False,
    "unknown_clients": 0,
}


def cmd_audit(args):
    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    findings, summary = audit(cfg)
    md = to_markdown(cfg, findings, summary)
    print(md)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        if args.format == "html":
            out.write_text(to_html(cfg, findings, summary), encoding="utf-8")
        elif args.format == "json":
            out.write_text(json.dumps({"summary": summary, "findings": [f.to_dict() for f in findings]},
                                      indent=2), encoding="utf-8")
        else:
            out.write_text(md, encoding="utf-8")
        print(f"\nSaved {args.format} report to {out}")
    return 0 if summary["failed"] == 0 else 1


def cmd_passphrase(_args):
    pw = getpass.getpass("Passphrase (hidden, not stored): ")
    r = evaluate(pw)
    print(f"Length: {r['length']}  Estimated entropy: {r['entropy_bits']} bits  Rating: {r['rating']}")
    for issue in r["issues"]:
        print(f" - {issue}")
    return 0


def cmd_local(_args):
    info = current_connection()
    if not info:
        print("Could not read the current Wi-Fi connection (not connected, no Wi-Fi adapter, or unsupported OS).")
        return 2
    print("Current connection:")
    for k, v in info.items():
        print(f"  {k}: {v}")
    findings, _ = audit(info)
    for f in findings:
        if f.id in ("SEC-01", "ENC-01") and f.status != "UNKNOWN":
            print(f"  [{f.status}] {f.area}: {f.observed}")
    return 0


def cmd_template(_args):
    print(json.dumps(TEMPLATE, indent=2))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit", help="audit a router configuration JSON file")
    a.add_argument("config")
    a.add_argument("--format", choices=["md", "html", "json"], default="md")
    a.add_argument("--out", help="write the report to this file")
    a.set_defaults(func=cmd_audit)
    sub.add_parser("passphrase", help="check passphrase strength").set_defaults(func=cmd_passphrase)
    sub.add_parser("local", help="inspect this computer's Wi-Fi connection").set_defaults(func=cmd_local)
    sub.add_parser("template", help="print blank config template").set_defaults(func=cmd_template)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
