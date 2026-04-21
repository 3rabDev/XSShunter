#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time

from colorama import Fore, Style, init

from modules.crawler import crawl_site
from modules.scanner import scan_url
from modules.utils import color_print, load_payloads, read_targets_from_file, save_report

init(autoreset=True)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logging.getLogger("urllib3").setLevel(logging.ERROR)

VERSION = "1.5"

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
║                          Advanced XSS Exploitation Framework                     ║
║                         v{VERSION} | @i3rrb | https://3rabdev.online                 ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""


def create_arg_parser():
    parser = argparse.ArgumentParser(
        description="XSShunter - Next-Generation XSS Discovery Engine",
        epilog="Example: python xssHunter.py -u http://test.com --crawl --dom --headless -o report.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("-u", "--url", help="Single target URL")
    target_group.add_argument("-f", "--file", help="File containing list of URLs (one per line)")
    target_group.add_argument("--crawl", action="store_true", help="Enable intelligent crawling mode")
    target_group.add_argument("--depth", type=int, default=2, help="Crawling depth (default: 2, max: 5)")
    target_group.add_argument("--same-domain", action="store_true", default=True, help="Stay on same domain during crawl")

    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    scan_group.add_argument("--cookie", help="Custom Cookie header (format: 'name=value; name2=value2')")
    scan_group.add_argument("--header", action="append", help="Custom headers (can be used multiple times)")
    scan_group.add_argument("--data", help="POST data for form submission (JSON or key=value&...)")
    scan_group.add_argument("--blind", action="store_true", help="Enable Blind XSS detection with callback")
    scan_group.add_argument("--dom", action="store_true", help="Enable deep DOM analysis")
    scan_group.add_argument("--headless", action="store_true", help="Verify with headless browser")
    scan_group.add_argument("--waf", action="store_true", help="Detect and attempt WAF bypass")
    scan_group.add_argument("-p", "--payloads", help="Custom payloads file path")
    scan_group.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")

    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", help="Save report to file (supports .json, .html, .txt)")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    output_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    output_group.add_argument("--quiet", action="store_true", help="Suppress all output except findings")

    misc_group = parser.add_argument_group("Misc Options")
    misc_group.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    misc_group.add_argument("--delay", type=float, default=0.1, help="Delay between requests (default: 0.1)")
    misc_group.add_argument("--user-agent", help="Custom User-Agent string")
    misc_group.add_argument("--version", action="store_true", help="Show version and exit")
    return parser


def validate_args(args):
    if args.version:
        print(f"XSShunter v{VERSION} | @i3rrb | https://3rabdev.online")
        raise SystemExit(0)
    if not args.url and not args.file:
        color_print("No target specified. Use -u or -f.", "error")
        raise SystemExit(1)
    args.depth = max(1, min(args.depth, 5))
    args.threads = max(1, min(args.threads, 100))
    args.timeout = max(1, args.timeout)
    args.delay = max(0.0, args.delay)
    return args


def process_headers(args):
    headers = {}
    if args.user_agent:
        headers["User-Agent"] = args.user_agent
    for header in args.header or []:
        if ":" not in header:
            continue
        key, value = header.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key:
            headers[key] = value
    return headers


def iter_targets(args):
    if args.file:
        color_print(f"Loading targets from {args.file}", "info", quiet=args.quiet)
        urls = read_targets_from_file(args.file)
        color_print(f"Loaded {len(urls)} targets", "success", quiet=args.quiet)
        return urls
    if args.crawl and args.url:
        urls = crawl_site(
            start_url=args.url,
            threads=args.threads,
            depth=args.depth,
            same_domain=args.same_domain,
            delay=args.delay,
            headers=args.headers,
            cookie=args.cookie,
            timeout=args.timeout,
        )
        if args.url not in urls:
            urls.insert(0, args.url)
        color_print(f"Crawled {len(urls)} unique URLs", "success", quiet=args.quiet)
        return urls
    return [args.url]


def save_if_requested(args, findings):
    if not args.output:
        return
    fmt = os.path.splitext(args.output)[1].lower().lstrip(".") or "json"
    if fmt not in {"json", "html", "txt"}:
        fmt = "json"
    save_report(findings, args.output, fmt)
    color_print(f"Report saved to {args.output} ({fmt})", "success", quiet=args.quiet)


def main():
    if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
        import io

        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    parser = create_arg_parser()
    args = validate_args(parser.parse_args())

    if args.no_color:
        init(autoreset=True, strip=True)

    if not any(flag in sys.argv for flag in ["-h", "--help", "--version"]) and not args.quiet:
        print(BANNER)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    args.headers = process_headers(args)

    try:
        payloads = load_payloads(args.payloads or "core/payloads.txt")
    except OSError as exc:
        color_print(f"Failed to load payloads: {exc}", "error")
        raise SystemExit(1)

    color_print(f"Loaded {len(payloads)} payloads", "info", quiet=not args.verbose)

    start_time = time.time()
    findings = []

    try:
        for index, url in enumerate(iter_targets(args), start=1):
            color_print(f"Scanning [{index}]: {url}", "info", quiet=args.quiet)
            findings.extend(scan_url(url, payloads, args))
    except KeyboardInterrupt:
        color_print("Scan interrupted by user", "warning")
        raise SystemExit(130)
    except Exception as exc:
        if args.verbose:
            logging.exception("Fatal scanning error")
        color_print(f"Fatal error: {exc}", "error")
        raise SystemExit(1)

    elapsed = time.time() - start_time
    unique_findings = deduplicate_findings(findings)

    if unique_findings:
        color_print(f"Scan complete: {len(unique_findings)} findings in {elapsed:.2f}s", "critical")
    else:
        color_print(f"Scan complete: no findings in {elapsed:.2f}s", "info", quiet=args.quiet)

    try:
        save_if_requested(args, unique_findings)
    except Exception as exc:
        color_print(f"Failed to save report: {exc}", "error")


def deduplicate_findings(findings):
    seen = set()
    unique = []
    for finding in findings:
        key = (
            finding.get("url"),
            finding.get("parameter"),
            finding.get("payload"),
            finding.get("type"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


if __name__ == "__main__":
    main()
