# Python Log Analyzer for Security

## Overview
This project is a Python-based tool designed to analyze web server access logs for suspicious activities. It parses log files line by line, identifies potential security threats based on predefined patterns, and generates a concise summary report.

This tool demonstrates fundamental skills in defensive security and log analysis, which are crucial for any Cybersecurity Analyst or Blue Team role.

---

## Features
- **Log Parsing:** Reads and processes standard web server `access.log` files.
- **Pattern Detection:** Uses regular expressions to detect a variety of potential attacks, including:
    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - Directory Traversal
    - Attempts to access sensitive admin or login pages.
- **Statistical Analysis:** Counts and ranks the most active IP addresses found in the log file.
- **Report Generation:** Displays a clean, readable report of all findings directly in the console.

---

## Technologies Used
- **Language:** Python 3
- **Core Libraries:**
    - `re` (for regular expression matching)
    - `collections.Counter` (for efficient counting and statistics)

---

## Setup and Usage
1.  Ensure you have Python 3 installed on your system.
2.  Place the `log_analyzer.py` script and the `access.log` file in the same directory.
3.  Navigate to that directory using your terminal or command prompt.
4.  Run the script with the following command:
    ```bash
    python log_analyzer.py
    ```
The script will automatically analyze the log file and print the security report to the console.

---

## Sample Output

```
[INFO] Starting analysis of file: access.log

[INFO] Analysis complete. Found 6 suspicious entries.

==================================================
      Server Log Security Analysis Report
==================================================

--- [!] Detected Suspicious Activities ---

  [+] Line: 3
      - Potential Attack Type: SQL Injection
      - Log Entry: 10.0.0.5 - - [28/Jun/2025:01:17:30 +0000] "GET /products/item1?id=1' or '1'='1 HTTP/1.1" 404 430

  [+] Line: 5
      - Potential Attack Type: Cross-Site Scripting (XSS)
      - Log Entry: 10.0.0.5 - - [28/Jun/2025:01:19:05 +0000] "GET /search?query=<script>alert('XSS')</script> HTTP/1.1" 404 430

... (and other findings) ...

--- [📊] Top 5 Most Active IP Addresses ---

  [+] IP Address: 10.0.0.5  |  Request Count: 4
  [+] IP Address: 172.16.0.10  |  Request Count: 3
  [+] IP Address: 192.168.1.1  |  Request Count: 2
  [+] IP Address: 192.168.1.2  |  Request Count: 1
  [+] IP Address: 192.168.1.3  |  Request Count: 1

==================================================
            End of Report
==================================================
```
