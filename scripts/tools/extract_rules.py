import os
import re

def parse_owasp(directory):
    rules = []
    # Simplified parser: SecRule TARGET "@rx REGEX" "id:XXX,..."
    rx_pattern = re.compile(r'SecRule\s+([^\s]+)\s+"@rx\s+([^"]+)"\s+.*?"id:([0-9]+)')
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.conf'):
                with open(os.path.join(root, file), 'r', errors='ignore') as f:
                    content = f.read()
                    
                    # Merge lines ending with \ 
                    lines = content.split('\n')
                    merged_lines = []
                    current_line = ""
                    for line in lines:
                        if line.endswith('\\'):
                            current_line += line[:-1].strip() + " "
                        else:
                            current_line += line.strip()
                            if current_line:
                                merged_lines.append(current_line)
                            current_line = ""
                            
                    for line in merged_lines:
                        match = rx_pattern.search(line)
                        if match:
                            target = match.group(1).replace(' ', '')
                            regex = match.group(2)
                            rule_id = match.group(3)
                            # All OWASP rules are HTTP related
                            rules.append((rule_id, target, regex))
    return rules

def parse_suricata(directory):
    rules = []
    # Simplified parser for pcre and content
    pcre_pattern = re.compile(r'pcre:"/([^/]+)/.*?";')
    content_pattern = re.compile(r'content:"([^"]+)";')
    sid_pattern = re.compile(r'sid:([0-9]+);')
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.rules'):
                with open(os.path.join(root, file), 'r', errors='ignore') as f:
                    for line in f:
                        if line.startswith('#'): continue
                        
                        # FILTER: Only process HTTP rules
                        # We look for $HTTP_PORTS, $HTTP_SERVERS, or explicit alert http
                        if '$HTTP_' not in line and 'alert http' not in line:
                            continue
                            
                        sid_match = sid_pattern.search(line)
                        if not sid_match: continue
                        rule_id = sid_match.group(1)
                        
                        # For HTTP rules, check if they target specific HTTP buffers
                        target = "HTTP_PAYLOAD" # Default broad HTTP target
                        if 'http_uri' in line:
                            target = "HTTP_URI"
                        elif 'http_header' in line or 'http_cookie' in line:
                            target = "HTTP_HEADERS"
                        elif 'http_client_body' in line:
                            target = "HTTP_BODY"
                        
                        pcre_match = pcre_pattern.search(line)
                        if pcre_match:
                            regex = pcre_match.group(1)
                            rules.append((rule_id, target, regex))
                        else:
                            content_match = content_pattern.search(line)
                            if content_match:
                                regex = re.escape(content_match.group(1))
                                rules.append((rule_id, target, regex))
                                
    return rules

def main():
    owasp_rules = parse_owasp('owasp-rules')
    suricata_rules = parse_suricata('rules')
    
    all_rules = owasp_rules + suricata_rules
    print(f"Extracted {len(owasp_rules)} OWASP rules.")
    print(f"Extracted {len(suricata_rules)} Suricata HTTP rules.")
    
    with open('hyperscan_rules.txt', 'w') as f:
        # Deduplicate by ID just in case
        seen = set()
        for r_id, target, regex in all_rules:
            if r_id not in seen:
                seen.add(r_id)
                # Ensure no tabs in regex or target
                regex_clean = regex.replace('\t', ' ').replace('\n', '')
                f.write(f"{r_id}\t{target}\t{regex_clean}\n")
    print(f"Wrote {len(seen)} HTTP rules to hyperscan_rules.txt")

if __name__ == '__main__':
    main()
