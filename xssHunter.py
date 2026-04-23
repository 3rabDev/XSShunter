#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time
from typing import List, Optional, Tuple

from colorama import Fore, Style, init

from modules.blind_collector import export_blind_findings, reset_blind_storage, start_collector, stop_collector
from modules.crawler import crawl_site
from modules.headless import check_chrome_setup
from modules.scanner import scan_url
from modules.utils import ScanConfig, color_print, config_to_dict, dedupe_findings, load_payloads, read_targets_from_file, save_report

init(autoreset=True)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logging.getLogger("urllib3").setLevel(logging.ERROR)

VERSION = "1.6"

BANNER = f"""
{Fore.RED}
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║   ██╗  ██╗███████╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████████╗███████╗   ║
║   ╚██╗██╔╝██╔════╝██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══██╔══██████╗    ║
║    ╚███╔╝ ███████╗███████╗    ███████║██║   ██║██╔██╗ ██║   ██║  ██║  ╚════██╗   ║
║    ██╔██╗ ╚════██║╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║  ██║  ███████║   ║
║   ██╔╝ ██╗███████║███████║    ██║  ██║╚██████╔╝██║ ╚████║   ██║  ██║  ██╔═══██║  ║
║   ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝  ╚═╝  ╚██████╔╝  ║
║                                                                                  ║
║                             Advanced XSS Discovery Framework                     ║
║                         v{VERSION} | @i3rrb | https://3rabdev.online             ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""


def is_valid_url(url: str) -> bool:
    """Validate URL format and scheme."""
    if not url or not isinstance(url, str):
        return False
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url.strip())
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False
        # Scheme must be http or https
        if parsed.scheme not in ("http", "https"):
            return False
        # Netloc must not be empty and should contain a dot or be localhost
        if "." not in parsed.netloc and parsed.netloc != "localhost":
            if not parsed.netloc.startswith("["):  # IPv6
                return False
        return True
    except Exception:
        return False


def create_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="XSShunter - Production-ready XSS discovery engine",
        epilog="Example: python xssHunter.py -u https://target.tld/search?q=1 --crawl --dom --headless -o report.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("-u", "--url", help="Single target URL")
    target_group.add_argument("-f", "--file", help="File containing target URLs")
    target_group.add_argument("--crawl", action="store_true", help="Enable crawling before scanning")
    target_group.add_argument("--crawl-js", action="store_true", help="Use JavaScript rendering during crawling (requires Selenium)")
    target_group.add_argument("--depth", type=int, default=2, help="Crawler depth (default: 2, max: 5)")
    target_group.add_argument("--same-domain", action="store_true", default=True, help="Restrict crawling to the starting domain")

    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("-t", "--threads", type=int, default=10, help="Worker thread count")
    scan_group.add_argument("--cookie", help="Cookie header value, example: session=abc; role=user")
    scan_group.add_argument("--header", action="append", help="Custom header, can be used multiple times")
    scan_group.add_argument("--data", help="POST data as JSON or key=value&key2=value2")
    scan_group.add_argument("--blind", action="store_true", help="Enable blind XSS payload dispatch")
    scan_group.add_argument("--blind-url", help="Blind XSS callback base URL")
    scan_group.add_argument("--start-collector", action="store_true", help="Start local blind XSS callback collector (default: localhost:8000)")
    scan_group.add_argument("--collector-port", type=int, default=8000, help="Port for blind XSS callback collector (default: 8000)")
    scan_group.add_argument("--collector-wait", type=int, default=30, help="Seconds to keep collector alive after scan (-1 keeps it running)")
    scan_group.add_argument("--dom", action="store_true", help="Enable DOM sink and source analysis")
    scan_group.add_argument("--headless", action="store_true", help="Verify findings using Selenium")
    scan_group.add_argument("--waf", action="store_true", help="Enable WAF-aware payload variants and detection")
    scan_group.add_argument("-p", "--payloads", help="Custom payload file")
    scan_group.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds")

    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", help="Output file path (.json, .html, .txt)")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    output_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    output_group.add_argument("--quiet", action="store_true", help="Show only essential finding output")

    misc_group = parser.add_argument_group("Misc Options")
    misc_group.add_argument("--proxy", help="Proxy URL, example: http://127.0.0.1:8080")
    misc_group.add_argument("--delay", type=float, default=0.1, help="Delay between requests")
    misc_group.add_argument("--user-agent", help="Custom User-Agent header")
    misc_group.add_argument("--version", action="store_true", help="Show version and exit")
    misc_group.add_argument("--check-setup", action="store_true", help="Check if Chrome/Selenium is properly installed")
    return parser


def namespace_to_config(args: argparse.Namespace) -> ScanConfig:
    config = ScanConfig(**vars(args))
    config.depth = max(1, min(config.depth, 5))
    config.threads = max(1, min(config.threads, 100))
    config.timeout = max(1, int(config.timeout))
    config.delay = max(0.0, float(config.delay))
    config.headers = process_headers(config)
    return config


def validate_config(config: ScanConfig) -> ScanConfig:
    if config.version:
        print(f"XSShunter v{VERSION} | @i3rrb | https://3rabdev.online")
        raise SystemExit(0)
    if config.check_setup:
        is_available, message = check_chrome_setup()
        print(message)
        raise SystemExit(0 if is_available else 1)
    if not config.url and not config.file and not config.start_collector:
        color_print("No target specified. Use -u or -f.", "error")
        raise SystemExit(1)
    if config.url:
        config.url = config.url.strip()
        if not is_valid_url(config.url):
            color_print(
                f"Invalid URL format: {config.url}\n"
                f"URL must start with http:// or https:// and have a valid domain",
                "error"
            )
            raise SystemExit(1)
    if config.file:
        config.file = config.file.strip()
    config.collector_wait = max(-1, int(config.collector_wait))
    if config.blind and not config.blind_url:
        config.blind_url = os.getenv("XSSHUNTER_BLIND_URL")
    return config


def process_headers(config: ScanConfig):
    headers = {}
    if config.user_agent:
        headers["User-Agent"] = config.user_agent
    for header in config.header or []:
        if ":" not in header:
            continue
        key, value = header.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key:
            headers[key] = value
    return headers


def iter_targets(config: ScanConfig) -> List[str]:
    if config.file:
        color_print(f"Loading targets from {config.file}", "info", quiet=config.quiet)
        targets = read_targets_from_file(config.file)
        color_print(f"Loaded {len(targets)} target(s)", "success", quiet=config.quiet)
        return targets
    if config.crawl and config.url:
        targets = crawl_site(
            start_url=config.url,
            threads=config.threads,
            depth=config.depth,
            same_domain=config.same_domain,
            delay=config.delay,
            headers=config.headers,
            cookie=config.cookie,
            proxy=config.proxy,
            timeout=config.timeout,
            use_javascript=config.crawl_js,
        )
        if config.url not in targets:
            targets.insert(0, config.url)
        color_print(f"Crawled {len(targets)} URL(s)", "success", quiet=config.quiet)
        return targets
    return [config.url]


def save_if_requested(config: ScanConfig, findings, elapsed: float) -> None:
    if not config.output:
        return
    fmt = os.path.splitext(config.output)[1].lower().lstrip(".") or "json"
    if fmt not in {"json", "html", "txt"}:
        fmt = "json"
    metadata = {
        "version": VERSION,
        "elapsed_seconds": round(elapsed, 2),
        "config": config_to_dict(config),
    }
    save_report(findings, config.output, fmt, metadata=metadata)
    color_print(f"Report saved to {config.output} ({fmt})", "success", quiet=config.quiet)


def main() -> None:
    if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
        import io

        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    parser = create_arg_parser()
    config = validate_config(namespace_to_config(parser.parse_args()))

    if config.no_color:
        init(autoreset=True, strip=True)

    if not any(flag in sys.argv for flag in ["-h", "--help", "--version"]) and not config.quiet:
        print(BANNER)

    if config.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        color_print("Verbose mode enabled", "info")

    # Start blind XSS callback collector if requested
    collector_info: Optional[Tuple] = None
    findings = []
    elapsed = 0.0
    try:
        if config.start_collector:
            reset_blind_storage()
            collector_info = start_collector(host="127.0.0.1", port=config.collector_port, daemon=True)
            if collector_info:
                color_print(
                    f"Blind XSS callback collector started on http://127.0.0.1:{config.collector_port}",
                    "success",
                    quiet=config.quiet
                )
                if not config.blind_url:
                    config.blind_url = f"http://127.0.0.1:{config.collector_port}"
                    color_print(
                        f"Set blind-url to {config.blind_url}",
                        "info",
                        quiet=config.quiet
                    )
            else:
                color_print("Failed to start callback collector", "warning", quiet=config.quiet)

        if not config.url and not config.file and config.start_collector:
            color_print("Collector-only mode running. Press Ctrl+C to stop.", "info", quiet=config.quiet)
            while True:
                time.sleep(1)

        payloads = load_payloads(config.payloads or "core/payloads.txt")
        color_print(f"Loaded {len(payloads)} payload(s)", "info", quiet=not config.verbose)
        if config.blind and not config.blind_url:
            color_print("Blind mode enabled without callback URL. Blind probes will be limited.", "warning", quiet=config.quiet)

        start_time = time.time()
        targets = iter_targets(config)
        for index, target in enumerate(targets, start=1):
            color_print(f"Scanning [{index}/{len(targets)}] {target}", "info", quiet=config.quiet)
            findings.extend(scan_url(target, payloads, config))

        elapsed = time.time() - start_time
        findings = dedupe_findings(findings)

        if findings:
            verified_count = sum(1 for finding in findings if finding.get("verified"))
            color_print(
                f"Scan complete: {len(findings)} finding(s), {verified_count} verified in {elapsed:.2f}s",
                "critical",
                quiet=False,
            )
        else:
            color_print(f"Scan complete: no findings in {elapsed:.2f}s", "info", quiet=config.quiet)

        try:
            save_if_requested(config, findings, elapsed)
        except Exception as exc:
            color_print(f"Failed to save report: {exc}", "error")
            raise SystemExit(1)

        if collector_info and config.start_collector and config.collector_wait != 0:
            if config.collector_wait < 0:
                color_print("Collector is still running. Press Ctrl+C to stop.", "info", quiet=config.quiet)
                while True:
                    time.sleep(1)
            else:
                color_print(f"Waiting {config.collector_wait}s for blind callbacks...", "info", quiet=config.quiet)
                time.sleep(config.collector_wait)
    except KeyboardInterrupt:
        color_print("Scan interrupted by user", "warning")
        raise SystemExit(130)
    except (FileNotFoundError, OSError) as exc:
        color_print(f"Failed to load payloads: {exc}", "error")
        raise SystemExit(1)
    except Exception as exc:
        if config.verbose:
            logging.exception("Fatal scanning error")
        color_print(f"Fatal error: {exc}", "error")
        raise SystemExit(1)
    finally:
        if collector_info and config.start_collector:
            blind_findings = export_blind_findings()
            if blind_findings:
                color_print(f"Blind XSS findings: {len(blind_findings)} marker(s) triggered", "critical", quiet=False)
                if config.verbose:
                    for finding in blind_findings:
                        color_print(f"  - {finding['marker']}: {finding['triggered_count']} callback(s)", "info")
            stop_collector(collector_info[0])


if __name__ == "__main__":
    main()
