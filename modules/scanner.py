#!/usr/bin/env python3

import concurrent.futures
import hashlib
import html
import logging
import re
import threading
import urllib.parse
import uuid
from typing import Dict, Iterable, List, Optional, Tuple

from modules.blind_collector import register_blind_marker
from modules.dom_analyzer import analyze_dom
from modules.headless import verify_xss
from modules.utils import build_blind_payloads, color_print, detect_waf, get_session, parse_data, random_delay

logger = logging.getLogger(__name__)


def detect_context(text: str, payload: str) -> str:
    escaped = re.escape(payload)
    patterns = [
        (rf"<script[^>]*>[^<]*{escaped}", "script block"),
        (rf"on\w+\s*=\s*[\"'][^\"']*{escaped}", "event handler"),
        (rf"javascript:[^\"'\s>]*{escaped}", "javascript uri"),
        (rf"<[^>]+\s\w+[^\n>]*{escaped}[^\n>]*>", "attribute"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return label
    return "reflection"


def build_query_urls(url: str, payload: str) -> Iterable[Tuple[str, str]]:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for parameter in params:
        candidate = {key: list(values) for key, values in params.items()}
        candidate[parameter] = [payload]
        query = urllib.parse.urlencode(candidate, doseq=True)
        request_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment)
        )
        yield parameter, request_url


def normalize_text(value: str) -> str:
    return value.replace("&quot;", '"').replace("&#x27;", "'").replace("&apos;", "'")


def reflected(response_text: str, payload: str) -> bool:
    if payload in response_text:
        return True
    if html.escape(payload) in response_text:
        return False
    return payload in normalize_text(response_text)


def baseline_hash(text: str) -> str:
    return hashlib.sha256(text[:10000].encode("utf-8", errors="ignore")).hexdigest()


def build_blind_marker(url: str, parameter: str, payload: str, index: int) -> str:
    base = f"{url}|{parameter}|{index}|{payload[:80]}|{uuid.uuid4().hex[:8]}"
    return "xsshunter-" + hashlib.sha1(base.encode("utf-8", errors="ignore")).hexdigest()[:20]


def build_payload_matrix(base_payloads: List[str], config) -> List[Dict[str, Optional[str]]]:
    variants: List[Dict[str, Optional[str]]] = [{"variant": "base", "payload": payload, "marker": None} for payload in base_payloads]
    
    if getattr(config, "waf", False):
        for payload in base_payloads:
            # URL encoding variants
            variants.append({"variant": "url_encoded", "payload": urllib.parse.quote(payload, safe=""), "marker": None})
            variants.append({"variant": "double_url_encoded", "payload": urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""), "marker": None})
            variants.append({"variant": "triple_url_encoded", "payload": urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""), safe=""), "marker": None})
            
            # Case mutations for filter bypasses
            variants.append({"variant": "case_mutation", "payload": payload.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"), "marker": None})
            variants.append({"variant": "mixed_case", "payload": payload.replace("<img", "<ImG").replace("onerror=", "OnErRoR="), "marker": None})
            
            # HTML entity encoding
            variants.append({"variant": "html_entity", "payload": html.escape(payload), "marker": None})
            
            # Null byte injection
            variants.append({"variant": "null_byte", "payload": payload.replace(">", "\x00>"), "marker": None})
            
            # Comment insertion (may bypass pattern matching)
            if "<script>" in payload:
                variants.append({"variant": "comment_injection", "payload": payload.replace("<script>", "<script>/**/").replace("</script>", "/**/</script>"), "marker": None})
            
            # Unicode variations (U+0000-U+001F bypasses)
            variants.append({"variant": "unicode_variant", "payload": payload.replace(" ", "\u0020"), "marker": None})
            
            # Polyglot payload (JavaScript/HTML hybrid)
            if "alert" in payload.lower():
                variants.append({"variant": "polyglot", "payload": f"';{payload}//", "marker": None})
            
            # Fragmentation - useful against regex-based WAFs
            if len(payload) > 10:
                mid = len(payload) // 2
                frag = f"{payload[:mid]}'{payload[mid:]}"
                variants.append({"variant": "fragmented", "payload": frag, "marker": None})
            
            # Protocol manipulation (for vectors with URLs)
            if "http://" in payload or "https://" in payload:
                variants.append({"variant": "protocol_variant", "payload": payload.replace("https://", "http://"), "marker": None})
                variants.append({"variant": "protocol_variant2", "payload": payload.replace("http://", "//").replace("https://", "//"), "marker": None})
            
            # Event handler mutations
            event_handlers = ["onclick", "onerror", "onload", "onmouseover", "onfocus"]
            for handler in event_handlers:
                if handler in payload.lower():
                    # Try with spaces and equals variations
                    variants.append({"variant": f"event_variant_{handler}", "payload": payload.replace(f"{handler}=", f"{handler.upper()} = "), "marker": None})
    if getattr(config, "blind", False):
        variants.append({"variant": "blind", "payload": "__blind__", "marker": None})
    
    deduped: List[Dict[str, Optional[str]]] = []
    seen = set()
    for entry in variants:
        key = (entry["variant"], entry["payload"], entry["marker"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def scan_url(url: str, payloads: List[str], config) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    findings_lock = threading.Lock()
    parsed = urllib.parse.urlparse(url)
    session = get_session(
        cookie=getattr(config, "cookie", None),
        proxy=getattr(config, "proxy", None),
        timeout=getattr(config, "timeout", 15),
        headers=getattr(config, "headers", None),
        user_agent=getattr(config, "user_agent", None),
    )
    post_data = parse_data(getattr(config, "data", None))
    has_query_params = bool(urllib.parse.parse_qs(parsed.query, keep_blank_values=True)) or "=" in parsed.query
    payload_matrix = build_payload_matrix(payloads, config)
    quiet = getattr(config, "quiet", False)

    if not has_query_params and not post_data:
        color_print(f"No injectable parameters found in {url}", "warning", quiet=quiet)
        return findings

    baseline_response = None
    baseline_signature = None
    try:
        baseline_response = session.get(url, timeout=config.timeout, allow_redirects=True)
        baseline_signature = baseline_hash(baseline_response.text)
    except Exception:
        logger.debug("Baseline request failed for %s", url, exc_info=True)

    if getattr(config, "waf", False) and baseline_response is not None:
        waf_name = detect_waf(baseline_response)
        if waf_name:
            color_print(f"WAF detected on {url}: {waf_name}", "warning", quiet=quiet)

    if getattr(config, "dom", False):
        try:
            dom_report = analyze_dom(url, session, headless=getattr(config, "headless", False))
            with findings_lock:
                findings.extend(dom_report.get("findings", []))
        except Exception:
            logger.debug("DOM analysis failed for %s", url, exc_info=True)

    def record_finding(
        parameter: str,
        payload: str,
        request_url: str,
        response_text: str,
        finding_type: str,
        variant: str,
        reflected_value: bool = True,
        marker: Optional[str] = None,
    ) -> None:
        finding = {
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "context": detect_context(response_text, payload) if reflected_value else variant,
            "type": finding_type,
            "request_url": request_url,
            "variant": variant,
            "marker": marker,
            "verified": False,
        }
        if getattr(config, "headless", False) and reflected_value and finding_type in {"Reflected XSS", "POST XSS"}:
            finding["verified"] = verify_xss(request_url, payload, timeout=min(config.timeout, 10))
        with findings_lock:
            findings.append(finding)
        color_print(
            f"Finding: {finding_type} | {parameter} | {url}",
            "critical" if finding["verified"] else "warning",
            quiet=quiet and not finding["verified"],
        )

    def test_get(parameter: str, request_url: str, payload: str, variant: str, marker: Optional[str]) -> None:
        try:
            random_delay(0.0, getattr(config, "delay", 0.1))
            response = session.get(request_url, timeout=config.timeout, allow_redirects=True)
            response_signature = baseline_hash(response.text)
            if reflected(response.text, payload):
                record_finding(parameter, payload, request_url, response.text, "Reflected XSS", variant, reflected_value=True, marker=marker)
                return
            if variant == "blind" and response.ok and response_signature != baseline_signature:
                record_finding(parameter, payload, request_url, response.text, "Blind XSS Probe", variant, reflected_value=False, marker=marker)
        except Exception:
            logger.debug("GET test failed for %s", request_url, exc_info=True)

    def test_post(parameter: str, payload: str, variant: str, marker: Optional[str]) -> None:
        try:
            random_delay(0.0, getattr(config, "delay", 0.1))
            body = dict(post_data)
            body[parameter] = payload
            response = session.post(url, data=body, timeout=config.timeout, allow_redirects=True)
            response_signature = baseline_hash(response.text)
            if reflected(response.text, payload):
                record_finding(parameter, payload, url, response.text, "POST XSS", variant, reflected_value=True, marker=marker)
                return
            if variant == "blind" and response.ok and response_signature != baseline_signature:
                record_finding(parameter, payload, url, response.text, "Blind XSS Probe", variant, reflected_value=False, marker=marker)
        except Exception:
            logger.debug("POST test failed for %s", url, exc_info=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, getattr(config, "threads", 10))) as executor:
        futures = []
        if post_data:
            for parameter in post_data:
                for index, entry in enumerate(payload_matrix):
                    variant = entry["variant"]
                    payload = entry["payload"]
                    marker = entry["marker"]
                    if variant == "blind":
                        marker = build_blind_marker(url, parameter, payload, index)
                        register_blind_marker(marker)
                        for blind_entry in build_blind_payloads(getattr(config, "blind_url", None), marker=marker):
                            futures.append(executor.submit(test_post, parameter, blind_entry["payload"], variant, blind_entry["marker"]))
                        continue
                    futures.append(executor.submit(test_post, parameter, payload, variant, marker))
        else:
            for index, entry in enumerate(payload_matrix):
                variant = entry["variant"]
                payload = entry["payload"]
                for parameter, request_url in build_query_urls(url, payload):
                    marker = entry["marker"]
                    if variant == "blind":
                        marker = build_blind_marker(url, parameter, payload, index)
                        register_blind_marker(marker)
                        for blind_entry in build_blind_payloads(getattr(config, "blind_url", None), marker=marker):
                            for blind_parameter, blind_request_url in build_query_urls(url, blind_entry["payload"]):
                                if blind_parameter != parameter:
                                    continue
                                futures.append(executor.submit(test_get, blind_parameter, blind_request_url, blind_entry["payload"], variant, blind_entry["marker"]))
                        continue
                    futures.append(executor.submit(test_get, parameter, request_url, payload, variant, marker))
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception:
                logger.debug("Scanner worker failure", exc_info=True)
    return findings
