#!/usr/bin/env python3

import html
import json
import os
import random
import time
import warnings
from http.cookies import SimpleCookie
from urllib.parse import quote_plus

import requests
from colorama import Fore, Style, init
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

init(autoreset=True)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

try:
    _ua = UserAgent()
except Exception:
    _ua = None


def _default_user_agent():
    if _ua:
        try:
            return _ua.random
        except Exception:
            pass
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"


def parse_cookie_string(cookie_string):
    if not cookie_string:
        return {}
    parsed = SimpleCookie()
    parsed.load(cookie_string)
    cookies = {name: morsel.value for name, morsel in parsed.items()}
    if cookies:
        return cookies
    result = {}
    for chunk in cookie_string.split(";"):
        if "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name:
            result[name] = value
    return result


def parse_data(raw_data):
    if not raw_data:
        return {}
    try:
        parsed = json.loads(raw_data)
        if isinstance(parsed, dict):
            return {str(key): "" if value is None else str(value) for key, value in parsed.items()}
    except json.JSONDecodeError:
        pass
    result = {}
    for item in raw_data.split("&"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        if key:
            result[key] = value
    return result


def build_headers(extra_headers=None):
    headers = {
        "User-Agent": _default_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }
    if extra_headers:
        headers.update(extra_headers)
    return headers


def get_session(cookie=None, proxy=None, timeout=15, retries=2, headers=None):
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(build_headers(headers))
    if cookie:
        session.cookies.update(parse_cookie_string(cookie) if isinstance(cookie, str) else cookie)
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    session.verify = False
    session.request_timeout = timeout
    return session


def load_payloads(file_path="core/payloads.txt", extra_path=None):
    payloads = []
    seen = set()
    defaults = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg/onload=confirm(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ]
    for candidate in [file_path, extra_path]:
        if not candidate:
            continue
        if not os.path.exists(candidate):
            if candidate != "core/payloads.txt":
                raise OSError(f"Payload file not found: {candidate}")
            continue
        with open(candidate, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                payload = line.strip()
                if not payload or payload.startswith("#") or payload in seen:
                    continue
                seen.add(payload)
                payloads.append(payload)
    if not payloads:
        payloads = defaults[:]
    return payloads


def read_targets_from_file(path):
    if not os.path.exists(path):
        raise OSError(f"File not found: {path}")
    targets = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            target = line.strip()
            if target and not target.startswith("#"):
                targets.append(target)
    return targets


def save_report(findings, output_file, format="json"):
    directory = os.path.dirname(os.path.abspath(output_file))
    os.makedirs(directory, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    if format == "json":
        report = {
            "scanner": "XSShunter",
            "timestamp": stamp,
            "total_findings": len(findings),
            "findings": findings,
        }
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
        return
    if format == "txt":
        lines = [f"XSShunter Report - {stamp}", "=" * 60]
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"[{index}] URL: {finding.get('url', '')}",
                    f"    Parameter: {finding.get('parameter', '')}",
                    f"    Payload: {finding.get('payload', '')}",
                    f"    Type: {finding.get('type', '')}",
                    f"    Context: {finding.get('context', '')}",
                    f"    Verified: {finding.get('verified', False)}",
                    "",
                ]
            )
        with open(output_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines).rstrip() + "\n")
        return
    if format == "html":
        rows = []
        for finding in findings:
            rows.append(
                "<tr>"
                f"<td>{html.escape(str(finding.get('url', '')))}</td>"
                f"<td>{html.escape(str(finding.get('parameter', '')))}</td>"
                f"<td><code>{html.escape(str(finding.get('payload', '')))}</code></td>"
                f"<td>{html.escape(str(finding.get('type', '')))}</td>"
                f"<td>{html.escape(str(finding.get('context', '')))}</td>"
                f"<td>{html.escape(str(finding.get('verified', False)))}</td>"
                "</tr>"
            )
        page = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>XSShunter Report</title>"
            "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#10151d;color:#e7edf5}"
            "table{width:100%;border-collapse:collapse}th,td{border:1px solid #2d3948;padding:10px;text-align:left}"
            "th{background:#182231}tr:nth-child(even){background:#131c28}code{white-space:pre-wrap}</style>"
            "</head><body>"
            f"<h1>XSShunter Report</h1><p>Generated: {html.escape(stamp)}</p>"
            f"<p>Total Findings: {len(findings)}</p>"
            "<table><tr><th>URL</th><th>Parameter</th><th>Payload</th><th>Type</th><th>Context</th><th>Verified</th></tr>"
            + "".join(rows)
            + "</table></body></html>"
        )
        with open(output_file, "w", encoding="utf-8") as handle:
            handle.write(page)
        return
    raise ValueError(f"Unsupported format: {format}")


def detect_waf(response):
    signatures = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cf"],
        "Sucuri": ["sucuri", "x-sucuri"],
        "Akamai": ["akamai"],
        "Imperva": ["incapsula", "imperva", "x-iinfo"],
        "F5 Big-IP": ["bigip", "x-waf-event-info"],
        "ModSecurity": ["modsecurity", "mod_security"],
    }
    headers = " ".join(f"{key}:{value}" for key, value in response.headers.items()).lower()
    body = response.text.lower()
    for name, markers in signatures.items():
        if any(marker in headers or marker in body for marker in markers):
            return name
    return None


def color_print(message, level="info", end="\n", quiet=False):
    if quiet:
        return
    colors = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "error": Fore.RED,
        "warning": Fore.YELLOW,
        "critical": Fore.MAGENTA + Style.BRIGHT,
        "header": Fore.BLUE + Style.BRIGHT,
    }
    prefixes = {
        "info": "[*]",
        "success": "[+]",
        "error": "[-]",
        "warning": "[!]",
        "critical": "[!!!]",
        "header": "[>]",
    }
    color = colors.get(level, Fore.WHITE)
    prefix = prefixes.get(level, "[*]")
    print(f"{color}{prefix} {message}{Style.RESET_ALL}", end=end)


def random_delay(min_sec=0.05, max_sec=0.2):
    time.sleep(random.uniform(min_sec, max_sec))


def encode_payload(payload, method="url"):
    if method == "url":
        return quote_plus(payload)
    if method == "double_url":
        return quote_plus(quote_plus(payload))
    if method == "html_entity":
        return html.escape(payload)
    return payload
