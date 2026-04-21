#!/usr/bin/env python3

import concurrent.futures
import html
import logging
import re
import threading
import urllib.parse

from modules.dom_analyzer import analyze_dom
from modules.headless import verify_xss
from modules.utils import color_print, detect_waf, get_session, parse_data, random_delay

logger = logging.getLogger(__name__)


def detect_context(text, payload):
    escaped = re.escape(payload)
    if re.search(rf"<script[^>]*>[^<]*{escaped}", text, re.IGNORECASE):
        return "script block"
    if re.search(rf"on\w+\s*=\s*[\"'][^\"']*{escaped}", text, re.IGNORECASE):
        return "event handler"
    if re.search(rf"<[^>]+\s\w+[^\n>]*{escaped}[^\n>]*>", text, re.IGNORECASE):
        return "attribute"
    if re.search(rf"javascript:[^\"'\s>]*{escaped}", text, re.IGNORECASE):
        return "javascript uri"
    return "reflection"


def build_query_urls(url, payload):
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


def reflected(response_text, payload):
    if payload in response_text:
        return True
    if html.escape(payload) in response_text:
        return False
    return False


def scan_url(url, payloads, args):
    findings = []
    findings_lock = threading.Lock()
    parsed = urllib.parse.urlparse(url)
    session = get_session(
        cookie=getattr(args, "cookie", None),
        proxy=getattr(args, "proxy", None),
        timeout=getattr(args, "timeout", 15),
        headers=getattr(args, "headers", None),
    )
    post_data = parse_data(getattr(args, "data", None))
    has_query_params = bool(urllib.parse.parse_qs(parsed.query, keep_blank_values=True)) or "=" in parsed.query

    if not has_query_params and not post_data:
        color_print(f"No injectable parameters found in {url}", "warning", quiet=getattr(args, "quiet", False))
        return findings

    if getattr(args, "waf", False):
        try:
            baseline = session.get(url, timeout=args.timeout)
            waf_name = detect_waf(baseline)
            if waf_name:
                color_print(f"WAF detected on {url}: {waf_name}", "warning", quiet=getattr(args, "quiet", False))
        except Exception:
            logger.debug("WAF detection failed for %s", url, exc_info=True)

    if getattr(args, "dom", False):
        try:
            dom_report = analyze_dom(url, session, headless=getattr(args, "headless", False))
            for finding in dom_report.get("findings", []):
                findings.append(finding)
        except Exception:
            logger.debug("DOM analysis failed for %s", url, exc_info=True)

    def record_finding(parameter, payload, request_url, response_text, finding_type):
        finding = {
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "context": detect_context(response_text, payload),
            "type": finding_type,
            "request_url": request_url,
            "verified": False,
        }
        if getattr(args, "headless", False):
            finding["verified"] = verify_xss(request_url, payload, timeout=min(args.timeout, 10))
        with findings_lock:
            findings.append(finding)
        color_print(
            f"Possible XSS found: {url} | param={parameter} | type={finding_type}",
            "critical",
            quiet=getattr(args, "quiet", False) and not finding["verified"],
        )

    def test_get(parameter, request_url, payload):
        try:
            random_delay(0.0, getattr(args, "delay", 0.1))
            response = session.get(request_url, timeout=args.timeout, allow_redirects=True)
            if reflected(response.text, payload):
                record_finding(parameter, payload, request_url, response.text, "Reflected XSS")
        except Exception:
            logger.debug("GET test failed for %s", request_url, exc_info=True)

    def test_post(parameter, payload):
        try:
            random_delay(0.0, getattr(args, "delay", 0.1))
            body = dict(post_data)
            body[parameter] = payload
            response = session.post(url, data=body, timeout=args.timeout, allow_redirects=True)
            if reflected(response.text, payload):
                record_finding(parameter, payload, url, response.text, "POST XSS")
        except Exception:
            logger.debug("POST test failed for %s", url, exc_info=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(args, "threads", 10)) as executor:
        futures = []
        if post_data:
            for parameter in post_data:
                for payload in payloads:
                    futures.append(executor.submit(test_post, parameter, payload))
        else:
            for payload in payloads:
                for parameter, request_url in build_query_urls(url, payload):
                    futures.append(executor.submit(test_get, parameter, request_url, payload))
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception:
                logger.debug("Scanner worker failure", exc_info=True)
    return findings
