#!/usr/bin/env python3
import os
import re
import json
from pathlib import Path

RULES_DIR = Path("./rules")
OUTPUT_DIR = Path("./parsed_rules")

# Regex to parse the standard Suricata/Snort rule header and split out options
# Format: action proto src_ip src_port dir dst_ip dst_port (options)
RULE_HEADER_RE = re.compile(
    r'^(?P<action>[a-zA-Z]+)\s+'
    r'(?P<proto>[a-zA-Z0-9_-]+)\s+'
    r'(?P<src_ip>[^\s]+)\s+'
    r'(?P<src_port>[^\s]+)\s+'
    r'(?P<direction>->|<>)\s+'
    r'(?P<dst_ip>[^\s]+)\s+'
    r'(?P<dst_port>[^\s]+)\s+'
    r'\((?P<options>.*)\)\s*$',
    re.DOTALL
)

def parse_options(options_str):
    """
    Parses key-value options inside parentheses (msg:"..."; sid:123; content:"..."; ...)
    Handles quoted strings, escaping, and modifiers.
    """
    options = {}
    contents = []
    
    # Tokenize by semicolons while respecting quotes
    tokens = []
    current_token = []
    in_quotes = False
    escape = False

    for char in options_str:
        if char == '\\' and not escape:
            escape = True
            current_token.append(char)
            continue
        if char == '"' and not escape:
            in_quotes = not in_quotes
        if char == ';' and not in_quotes:
            token = "".join(current_token).strip()
            if token:
                tokens.append(token)
            current_token = []
        else:
            current_token.append(char)
        escape = False

    last_content = None

    for token in tokens:
        if ':' in token:
            key, val = token.split(':', 1)
            key = key.strip()
            val = val.strip().strip('"')

            if key == "content":
                content_entry = {"pattern": val, "modifiers": {}}
                contents.append(content_entry)
                last_content = content_entry
            elif key in ("offset", "depth", "distance", "within", "nocase", "fast_pattern") and last_content:
                last_content["modifiers"][key] = val
            elif key == "sid":
                try:
                    options["sid"] = int(val)
                except ValueError:
                    options["sid"] = val
            elif key == "rev":
                try:
                    options["rev"] = int(val)
                except ValueError:
                    options["rev"] = val
            else:
                if key in options:
                    if not isinstance(options[key], list):
                        options[key] = [options[key]]
                    options[key].append(val)
                else:
                    options[key] = val
        else:
            # Standalone flags (e.g. nocase, fast_pattern without value)
            flag = token.strip()
            if flag in ("nocase", "fast_pattern") and last_content:
                last_content["modifiers"][flag] = True
            else:
                options[flag] = True

    if contents:
        options["contents"] = contents

    return options

def parse_rule_line(line, source_file, line_num):
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    match = RULE_HEADER_RE.match(line)
    if not match:
        return None

    data = match.groupdict()
    options = parse_options(data.pop("options", ""))

    rule_dict = {
        "source_file": source_file,
        "line_number": line_num,
        "action": data["action"],
        "protocol": data["proto"].lower(),
        "src_ip": data["src_ip"],
        "src_port": data["src_port"],
        "direction": data["direction"],
        "dst_ip": data["dst_ip"],
        "dst_port": data["dst_port"],
        "options": options,
        "raw_rule": line
    }
    return rule_dict

def main():
    if not RULES_DIR.exists():
        print(f"Directory {RULES_DIR} not found.")
        return

    OUTPUT_DIR.mkdir(exist_ok=True)
    
    # Store parsed rules grouped by protocol
    protocol_rules = {}
    stats = {}

    total_parsed = 0
    rule_files = list(RULES_DIR.glob("*.rules"))

    print(f"🔍 Parsing {len(rule_files)} rule files from '{RULES_DIR}'...")

    for file_path in rule_files:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                parsed = parse_rule_line(line, file_path.name, line_num)
                if parsed:
                    proto = parsed["protocol"]
                    protocol_rules.setdefault(proto, []).append(parsed)
                    stats[proto] = stats.get(proto, 0) + 1
                    total_parsed += 1

    print(f"\n✅ Total Rules Parsed: {total_parsed}")
    print("\n📊 Breakdown by Protocol:")
    for proto, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {proto.upper():<10}: {count:>6} rules")

    print(f"\n💾 Saving JSON outputs grouped into '{OUTPUT_DIR}'...")

    for proto, rules in protocol_rules.items():
        proto_dir = OUTPUT_DIR / proto
        proto_dir.mkdir(exist_ok=True)

        # 1. Save aggregated protocol JSON
        agg_file = proto_dir / f"all_{proto}_rules.json"
        with open(agg_file, "w", encoding="utf-8") as out:
            json.dump(rules, out, indent=2)

        # 2. Save grouped by source file inside the protocol folder
        files_map = {}
        for r in rules:
            files_map.setdefault(r["source_file"], []).append(r)

        for src_name, src_rules in files_map.items():
            base_name = Path(src_name).stem
            out_file = proto_dir / f"{base_name}.json"
            with open(out_file, "w", encoding="utf-8") as out:
                json.dump(src_rules, out, indent=2)

    print(f"🎉 Done! All parsed rule JSONs are in '{OUTPUT_DIR.resolve()}'.")

if __name__ == "__main__":
    main()

