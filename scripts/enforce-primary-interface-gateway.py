#!/usr/bin/env python3
"""Enforce a gateway on one primary interface without changing other NICs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise SystemExit("PyYAML is required: apt install python3-yaml") from exc


def update_manifest(path: Path, interface: str, gateway: str, check: bool) -> bool:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    interfaces = data.get("spec", {}).get("interfaces", [])
    matches = [item for item in interfaces if item.get("name") == interface]
    if len(matches) != 1:
        raise ValueError(f"{path}: expected exactly one {interface} interface, found {len(matches)}")

    changed = matches[0].get("gateway") != gateway
    matches[0]["gateway"] = gateway

    for item in interfaces:
        if item.get("name") != interface and item.get("gateway") not in (None, ""):
            raise ValueError(
                f"{path}: secondary interface {item.get('name')} unexpectedly has gateway={item.get('gateway')}"
            )

    if changed and not check:
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path, help="Node YAML file or directory")
    parser.add_argument("--interface", default="ens33")
    parser.add_argument("--gateway", default="1.0.0.1")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    files = [args.path] if args.path.is_file() else sorted(args.path.glob("*.yaml"))
    if not files:
        parser.error(f"no YAML files found under {args.path}")

    changed = 0
    for path in files:
        try:
            changed += int(update_manifest(path, args.interface, args.gateway, args.check))
        except (ValueError, AttributeError, yaml.YAMLError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    if args.check and changed:
        print(f"ERROR: {changed} manifest(s) do not enforce {args.interface} gateway {args.gateway}", file=sys.stderr)
        return 1

    verb = "validated" if args.check else "updated"
    print(f"{verb} {len(files)} manifest(s); changed={changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
