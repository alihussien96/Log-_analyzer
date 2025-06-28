import re
from collections import Counter

# --- Suspicious Pattern Definitions ---
SUSPICIOUS_PATTERNS = {
    "SQL Injection": re.compile(r"(union|select|insert|delete|update|--|;|\'|\")", re.IGNORECASE),
    "Cross-Site Scripting (XSS)": re.compile(r"(<script>|%3Cscript%3E|alert\(|javascript:)", re.IGNORECASE),
    "Directory Traversal": re.compile(r"\.\./|\.\.\\"),
    "Failed Login/Admin Access": re.compile(r"wp-login\.php|/admin", re.IGNORECASE)
}

def analyze_log_file(file_path):
    """Analyzes the log file for suspicious patterns."""
    print(f"[INFO] Starting analysis of file: {file_path}\n")
    suspicious_entries = []
    ip_counter = Counter()

    try:
        # Open and read the log file
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                # Update IP counter for each line
                ip_match = re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if ip_match:
                    ip_counter[ip_match.group(1)] += 1

                # Search for suspicious patterns in the line
                for attack_type, pattern in SUSPICIOUS_PATTERNS.items():
                    if pattern.search(line):
                        # Record the finding
                        entry = {
                            "line_number": line_num,
                            "attack_type": attack_type,
                            "log_entry": line.strip()
                        }
                        suspicious_entries.append(entry)
                        break
    
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None, None
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        return None, None

    print(f"[INFO] Analysis complete. Found {len(suspicious_entries)} suspicious entries.")
    return suspicious_entries, ip_counter

def generate_report(suspicious_entries, ip_counter):
    """Generates and prints a summary report of the analysis."""
    print("\n" + "="*50)
    print("      Server Log Security Analysis Report")
    print("="*50 + "\n")

    # Report on detected suspicious activities
    if suspicious_entries:
        print("--- [!] Detected Suspicious Activities ---\n")
        for entry in suspicious_entries:
            print(f"  [+] Line: {entry['line_number']}")
            print(f"      - Potential Attack Type: {entry['attack_type']}")
            print(f"      - Log Entry: {entry['log_entry']}\n")
    else:
        print("--- [✓] No clear suspicious activities were detected. ---\n")

    # Report on top IP addresses
    if ip_counter:
        print("--- [📊] Top 5 Most Active IP Addresses ---\n")
        for ip, count in ip_counter.most_common(5):
            print(f"  [+] IP Address: {ip}  |  Request Count: {count}")

    print("\n" + "="*50)
    print("            End of Report")
    print("="*50)


# --- Main Execution Block ---
if __name__ == "__main__":
    log_file = 'access.log'
    found_entries, top_ips = analyze_log_file(log_file)
    
    if found_entries is not None:
        generate_report(found_entries, top_ips)
