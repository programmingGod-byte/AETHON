#!/usr/bin/env python3
import json
import re
import os
from pathlib import Path

INPUT_DIR = Path("./parsed_rules")
OUTPUT_DIR = Path("./used-rules")

def parse_suricata_pattern(raw_pattern):
    """
    Parses Suricata pattern string, handling negation (!) and hex bytes (|xx yy|).
    Returns (regex_escaped_string, is_negated)
    """
    is_negated = False
    
    # Check for negation
    if raw_pattern.startswith('!'):
        is_negated = True
        raw_pattern = raw_pattern[1:]
        
    # Remove rogue quotes if left over from negation (e.g., !"pattern")
    if raw_pattern.startswith('"'):
        raw_pattern = raw_pattern[1:]
    if raw_pattern.endswith('"'):
        raw_pattern = raw_pattern[:-1]
        
    # Split by hex blocks
    parts = re.split(r'(\|[^|]+\|)', raw_pattern)
    regex_part = ""
    
    for p in parts:
        if p.startswith('|') and p.endswith('|'):
            hex_bytes = p[1:-1].split()
            for hb in hex_bytes:
                # Basic validation for 2-char hex
                if len(hb) == 2 and all(c in "0123456789abcdefABCDEF" for c in hb):
                    regex_part += f"\\x{hb.lower()}"
        else:
            # Escape literal characters for PCRE regex
            regex_part += re.escape(p)
            
    return regex_part, is_negated

def convert_rule_to_hyperscan(rule):
    """
    Converts a parsed JSON rule into a Hyperscan-ready flat object.
    """
    options = rule.get("options", {})
    contents = options.get("contents", [])
    sid = options.get("sid")
    
    # We need a SID and at least one content payload to scan
    if not sid or not contents:
        return None
        
    regex_chain = []
    negated_patterns = []
    
    for i, c in enumerate(contents):
        pattern = c.get("pattern", "")
        modifiers = c.get("modifiers", {})
        
        regex_val, is_negated = parse_suricata_pattern(pattern)
        
        if is_negated:
            negated_patterns.append({
                "regex": regex_val,
                "modifiers": modifiers
            })
            continue
            
        # Apply Case Insensitivity locally for this content match
        if modifiers.get("nocase"):
            regex_val = f"(?i){regex_val}(?-i)"
            
        # Calculate Regex spacing based on distance/within
        if len(regex_chain) > 0:
            dist = modifiers.get("distance", "")
            within = modifiers.get("within", "")
            
            if str(dist).isdigit() and str(within).isdigit():
                max_dist = int(dist) + int(within)
                regex_chain.append(f".{{{dist},{max_dist}}}?")
            elif str(dist).isdigit():
                regex_chain.append(f".{{{dist},}}?")
            elif str(within).isdigit():
                regex_chain.append(f".{{0,{within}}}?")
            else:
                regex_chain.append(".*?")
                
        regex_chain.append(regex_val)
        
    # If a rule only contained negative matches, we can't use it as a primary Hyperscan trigger easily
    if not regex_chain:
        return None
        
    final_regex = "".join(regex_chain)
    
    # Extract offset and depth from the first positive pattern for C++ Phase 2 verification
    first_offset = None
    first_depth = None
    for c in contents:
        pattern = c.get("pattern", "")
        if not pattern.startswith("!"):
            mods = c.get("modifiers", {})
            if "offset" in mods:
                try:
                    first_offset = int(mods["offset"])
                except ValueError:
                    first_offset = mods["offset"]
            if "depth" in mods:
                try:
                    first_depth = int(mods["depth"])
                except ValueError:
                    first_depth = mods["depth"]
            break

    return {
        "id": int(sid),
        "regex": final_regex,
        "flags": ["HS_FLAG_DOTALL", "HS_FLAG_SINGLEMATCH"],
        "offset": first_offset,
        "depth": first_depth,
        "src_ip": rule.get("src_ip"),
        "src_port": rule.get("src_port"),
        "direction": rule.get("direction"),
        "dst_ip": rule.get("dst_ip"),
        "dst_port": rule.get("dst_port"),
        "protocol": rule.get("protocol"),
        "msg": options.get("msg", ""),
        "classtype": options.get("classtype", ""),
        "negated_patterns": negated_patterns
    }

def main():
    if not INPUT_DIR.exists():
        print(f"Directory {INPUT_DIR} not found. Please run the rule parser first.")
        return
        
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    total_converted = 0
    
    print(f"🚀 Compiling Parsed Rules to Hyperscan Regexes...")
    
    # Iterate through each protocol folder
    for proto_dir in [d for d in INPUT_DIR.iterdir() if d.is_dir()]:
        proto_name = proto_dir.name
        agg_file = proto_dir / f"all_{proto_name}_rules.json"
        
        if not agg_file.exists():
            continue
            
        with open(agg_file, "r", encoding="utf-8") as f:
            parsed_rules = json.load(f)
            
        hyperscan_rules = []
        for rule in parsed_rules:
            hs_rule = convert_rule_to_hyperscan(rule)
            if hs_rule:
                hyperscan_rules.append(hs_rule)
                
        if hyperscan_rules:
            out_file = OUTPUT_DIR / f"hyperscan_{proto_name}.json"
            with open(out_file, "w", encoding="utf-8") as out:
                json.dump(hyperscan_rules, out, indent=2)
            print(f"  ✅ Compiled {len(hyperscan_rules):>5} rules for '{proto_name.upper()}' -> {out_file.name}")
            total_converted += len(hyperscan_rules)
            
    print(f"\n🎉 Done! {total_converted} total rules successfully converted to Hyperscan Regex Format in '{OUTPUT_DIR}'")

if __name__ == "__main__":
    main()

