#!/usr/bin/env python3
"""Merge validated upstream broker domains with tracked local additions.

When rules/brokers.json defines a surge section, also write a Surge RULE-SET
from those domain lists plus the manually maintained extended file.
"""

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


def normalize_domain(value, number):
    value = value.lower()
    if not DOMAIN.fullmatch(value):
        raise ValueError(f"Line {number}: invalid domain {value!r}")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError(f"Line {number}: IP addresses are not domains")


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
        rules.add(f"{kind},{normalize_domain(value, number)}")
    return rules


def normalize_ipv4_cidr(value, number):
    """Validate an IPv4 CIDR and keep host bits that the manual list already uses."""
    address, separator, prefix = value.partition("/")
    if not separator:
        raise ValueError(f"Line {number}: invalid IP-CIDR {value!r}")
    try:
        ip = ipaddress.IPv4Address(address)
        length = int(prefix)
    except ValueError as error:
        raise ValueError(f"Line {number}: invalid IP-CIDR {value!r}") from error
    if prefix != str(length) or not 0 <= length <= 32:
        raise ValueError(f"Line {number}: invalid IP-CIDR {value!r}")
    return f"{ip}/{length}"


def parse_extended(text):
    """Rules kept for Surge: DOMAIN, DOMAIN-SUFFIX, and IPv4 IP-CIDR with no-resolve."""
    rules = set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [part.strip() for part in line.split(",")]
        kind = parts[0]
        if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            if len(parts) != 2:
                raise ValueError(f"Line {number}: only domain rules without policies are allowed")
            rule = f"{kind},{normalize_domain(parts[1], number)}"
        elif kind == "IP-CIDR":
            if len(parts) != 3 or parts[2] != "no-resolve":
                raise ValueError(f"Line {number}: IP-CIDR must keep no-resolve and omit a policy")
            rule = f"IP-CIDR,{normalize_ipv4_cidr(parts[1], number)},no-resolve"
        else:
            raise ValueError(f"Line {number}: unsupported Surge rule type {kind}")
        rules.add(rule)
    return rules


def rule_sort_key(rule):
    if rule.startswith("IP-CIDR,"):
        address, prefix = rule.split(",", 2)[1].split("/")
        return (1, ipaddress.IPv4Address(address).packed, int(prefix))
    return (0, rule)


def render_surge(config, broker_rules, extended_rules):
    """Build a Surge RULE-SET from broker domain rules plus the manual extended list."""
    surge = config["surge"]
    missing = [key for key in ("name", "output", "extended", "sources", "license", "sections") if key not in surge]
    if missing:
        raise ValueError(f"surge config missing {', '.join(missing)}")
    seen = set()
    blocks = []
    for section in surge["sections"]:
        title = section.get("title")
        if not title:
            raise ValueError("Surge section is missing a title")
        uses_extended = bool(section.get("extended"))
        if uses_extended == ("broker" in section):
            raise ValueError(f"Surge section {title!r} must reference either a broker or the extended list")
        if uses_extended:
            rules = extended_rules
        else:
            name = section["broker"]
            if name not in broker_rules:
                raise ValueError(f"Surge section {title!r} references unknown broker {name}")
            rules = broker_rules[name]
        lines = [f"# --- {title} ---"]
        for rule in sorted(rules, key=rule_sort_key):
            if rule in seen:
                continue
            seen.add(rule)
            lines.append(rule)
        blocks.append("\n".join(lines))
    description = surge.get("description", "Merged broker rules for Surge RULE-SET.")
    header = [
        f'# NAME: {surge["name"]}',
        f"# DESC: {description}",
        "# GENERATED: scripts/sync_broker_rules.py. Domain lists follow the shadowrocket outputs;",
        "# Futu_Extended, including its manually maintained IP-CIDR ranges, is merged from that file.",
        f'# SOURCES: {surge["sources"]}',
        f'# UPSTREAM LICENSE: {surge["license"]}',
        "# Public rule sources; not a complete app traffic capture.",
        f"# TOTAL: {len(seen)}",
    ]
    return "\n".join(header) + "\n\n" + "\n\n".join(blocks) + "\n", seen


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


def prepare_surge(root, config, broker_rules):
    surge = config["surge"]
    extended_path = root / surge["extended"]
    extended_rules = parse_extended(extended_path.read_text(encoding="utf-8"))
    if not extended_rules:
        raise ValueError(f'{surge["extended"]}: extended rule list is empty')
    new, new_rules = render_surge(config, broker_rules, extended_rules)
    target = root / surge["output"]
    old = target.read_text(encoding="utf-8") if target.exists() else ""
    old_rules = parse_extended(old) if old else set()
    removed = old_rules - new_rules
    if old_rules and len(removed) / len(old_rules) > 0.25:
        raise ValueError(f'{surge["name"]}: refusing to remove {len(removed)}/{len(old_rules)} Surge rules; review extended and broker lists')
    print(f'{surge["name"]}: surge={len(new_rules)}, added={len(new_rules - old_rules)}, removed={len(removed)}')
    if new != old:
        return [(target, old, new)]
    return []


def prepare(root, config, loader=fetch):
    """Download and validate every source before changing any output file."""
    pending = []
    broker_rules = {}
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
        broker_rules[broker["name"]] = rules
    if "surge" in config:
        pending.extend(prepare_surge(root, config, broker_rules))
    return pending


def sync(root=ROOT, check=False, loader=fetch):
    config = json.loads((root / "rules/brokers.json").read_text(encoding="utf-8"))
    pending = prepare(root, config, loader)
    for target, old, new in pending:
        if check:
            print("".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile=str(target), tofile=str(target))), end="")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
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
