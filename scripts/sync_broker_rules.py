#!/usr/bin/env python3
"""Merge validated upstream broker domains with tracked local additions."""

import argparse
import difflib
import ipaddress
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_BYTES = 1024 * 1024


def parse_rules(text, format_name):
    if format_name not in {"v2fly", "shadowrocket"}:
        raise ValueError(f"Unknown format: {format_name}")
    rules = set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if format_name == "v2fly":
            parts = line.split()
            if any(not re.fullmatch(r"@[\w-]+(?:=[\w-]+)?", tag) for tag in parts[1:]):
                raise ValueError(f"Line {number}: invalid v2fly attributes")
            value = parts[0]
            kind = "DOMAIN-SUFFIX"
            if ":" in value:
                prefix, value = value.split(":", 1)
                if prefix not in {"domain", "full"}:
                    raise ValueError(f"Line {number}: unsupported v2fly rule {prefix}")
                kind = "DOMAIN" if prefix == "full" else "DOMAIN-SUFFIX"
        else:
            parts = [part.strip() for part in line.split(",")]
            if len(parts) != 2 or parts[0] not in {"DOMAIN", "DOMAIN-SUFFIX"}:
                raise ValueError(f"Line {number}: only domain rules without policies are allowed")
            kind, value = parts
        value = value.lower()
        if not DOMAIN.fullmatch(value):
            raise ValueError(f"Line {number}: invalid domain {value!r}")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ValueError(f"Line {number}: IP addresses are not domains")
        rules.add(f"{kind},{value}")
    return rules


def fetch(url):
    for attempt in range(3):
        try:
            request = Request(url, headers={"User-Agent": "proxy-configs-rule-sync/1.0"})
            with urlopen(request, timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError(f"Upstream response exceeds {MAX_BYTES} bytes")
            return data.decode("utf-8-sig")
        except (URLError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def excluded(rule, suffixes):
    domain = rule.split(",", 1)[1]
    return any(domain == suffix or domain.endswith("." + suffix) for suffix in suffixes)


def prepare(root, config, loader=fetch):
    """Download and validate every source before changing any output file."""
    pending = []
    for broker in config["brokers"]:
        upstream = parse_rules(loader(broker["url"]), broker["format"])
        if not broker["min_rules"] <= len(upstream) <= 500:
            raise ValueError(f'{broker["name"]}: unexpected upstream rule count {len(upstream)}')
        if not set(broker["required"]).issubset(upstream):
            raise ValueError(f'{broker["name"]}: upstream is missing required core domains')
        local = parse_rules((root / broker["local"]).read_text(encoding="utf-8"), "shadowrocket")
        rules = {rule for rule in upstream | local if not excluded(rule, config["exclude_suffixes"])}
        if not set(broker["required"]).issubset(rules):
            raise ValueError(f'{broker["name"]}: exclusions removed core domains')
        target = root / broker["output"]
        old = target.read_text(encoding="utf-8") if target.exists() else ""
        old_rules = parse_rules(old, "shadowrocket")
        removed = old_rules - rules
        if old_rules and len(removed) / len(old_rules) > 0.25:
            raise ValueError(f'{broker["name"]}: refusing to remove {len(removed)}/{len(old_rules)} rules; review upstream/local rules')
        header = [
            f'# NAME: {broker["name"]}',
            '# GENERATED: scripts/sync_broker_rules.py; edit rules/local/*.list instead.',
            f'# SOURCE: {broker["url"]}',
            f'# UPSTREAM LICENSE: {broker["license"]}',
            f'# LOCAL: {broker["local"]}',
            '# MODIFIED: normalized, merged and filtered; change dates are recorded in git history.',
            '# Public rule sources; not a complete app traffic capture.',
            f'# TOTAL: {len(rules)}',
            '',
        ]
        new = "\n".join(header + sorted(rules)) + "\n"
        print(f'{broker["name"]}: upstream={len(upstream)}, local={len(local)}, output={len(rules)}, added={len(rules - old_rules)}, removed={len(removed)}')
        if new != old:
            pending.append((target, old, new))
    return pending


def sync(root=ROOT, check=False, loader=fetch):
    config = json.loads((root / "rules/brokers.json").read_text(encoding="utf-8"))
    pending = prepare(root, config, loader)
    for target, old, new in pending:
        if check:
            print("".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile=str(target), tofile=str(target))), end="")
        else:
            target.write_text(new, encoding="utf-8")
            print(f"Updated {target.relative_to(root)}")
    if not pending:
        print("Rules are already up to date.")
    return 1 if check and pending else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Show changes without writing; exit 1 if outdated")
    args = parser.parse_args()
    try:
        return sync(check=args.check)
    except (OSError, ValueError) as error:
        print(f"Rule sync failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
