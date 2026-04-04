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

import argparse
import sys
import json
import os
import time
from colorama import init, Fore, Style
from pyfiglet import figlet_format
from modules.scanner import scan_url
from modules.crawler import crawl_site
from modules.utils import load_payloads, save_report, color_print


init(autoreset=True)

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
║                         v1.0 | @i3rrb | https://3rabdev.online                   ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

def create_arg_parser():
    parser = argparse.ArgumentParser(
        description="XSShunter - Next-Generation XSS Discovery Engine",
        epilog="Example: python xssHunter.py -u http://test.com --crawl --dom --headless -o report.json",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument("-u", "--url", help="Single target URL")
    target_group.add_argument("-f", "--file", help="File containing list of URLs (one per line)")
    target_group.add_argument("--crawl", action="store_true", help="Enable intelligent crawling mode")
    target_group.add_argument("--depth", type=int, default=3, help="Crawling depth (default: 3, max: 5)")
    target_group.add_argument("--same-domain", action="store_true", default=True, help="Stay on same domain during crawl")

    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    scan_group.add_argument("--cookie", help="Custom Cookie header (format: 'name=value' or JSON)")
    scan_group.add_argument("--header", action='append', help="Custom headers (can be used multiple times)")
    scan_group.add_argument("--data", help="POST data for form submission (JSON or key=value&...")
    scan_group.add_argument("--blind", action="store_true", help="Enable Blind XSS detection with callback")
    scan_group.add_argument("--dom", action="store_true", help="Enable deep DOM analysis")
    scan_group.add_argument("--headless", action="store_true", help="Verify with headless browser")
    scan_group.add_argument("--waf", action="store_true", help="Detect and attempt WAF bypass")
    scan_group.add_argument("-p", "--payloads", help="Custom payloads file path")
    scan_group.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")

    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument("-o", "--output", help="Save report to file (supports .json, .html, .txt)")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    output_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    output_group.add_argument("--quiet", action="store_true", help="Suppress all output except findings")

    misc_group = parser.add_argument_group('Misc Options')
    misc_group.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    misc_group.add_argument("--delay", type=float, default=0.1, help="Delay between requests (default: 0.1)")
    misc_group.add_argument("--user-agent", help="Custom User-Agent string")
    misc_group.add_argument("--version", action="store_true", help="Show version and exit")
    return parser

def validate_args(args):
    if args.version:
        print(f"XSShunter v1.5 | @i3rrb | https://3arabdev.online")
        sys.exit(0)
    if not args.url and not args.file:
        color_print("No target specified. Use -u or -f.", "error")
        sys.exit(1)
    if args.crawl and args.depth > 5:
        color_print("Max depth is 5, reducing to 5", "warning")
        args.depth = 5
    if args.threads < 1 or args.threads > 100:
        color_print("Threads must be between 1 and 100, using 20", "warning")
        args.threads = 20
    return args

def process_headers(args):
    headers = {}
    if args.cookie:
        headers['Cookie'] = args.cookie
    if args.user_agent:
        headers['User-Agent'] = args.user_agent
    if args.header:
        for h in args.header:
            if ':' in h:
                key, val = h.split(':', 1)
                headers[key.strip()] = val.strip()
    return headers

def main():
    if not sys.flags.interactive:
        try:
            import warnings
            warnings.filterwarnings("ignore")
        except:
            pass

    if not any(arg in sys.argv for arg in ['--no-color', '-h', '--help']):
        print(BANNER)

    parser = create_arg_parser()
    args = parser.parse_args()
    args = validate_args(args)

    if args.no_color:
        init(autoreset=True, strip=True)

    headers = process_headers(args)

    payloads = load_payloads(args.payloads if args.payloads else "core/payloads.txt")

    headers = process_headers(args)

    payloads = load_payloads(args.payloads if args.payloads else "core/payloads.txt")
    if args.verbose:
        color_print(f"Loaded {len(payloads)} XSS payloads", "info")

    findings = []
    start_time = time.time()
    args.headers = headers

    try:
        if args.crawl and args.url:
            color_print(f"Starting intelligent crawl on {args.url} (depth={args.depth}, threads={args.threads})", "header")
            urls = crawl_site(
                start_url=args.url,
                threads=args.threads,
                depth=args.depth,
                same_domain=args.same_domain,
                delay=args.delay
            )
            color_print(f"Crawled {len(urls)} unique URLs", "success")
            for idx, url in enumerate(urls, 1):
                if not args.quiet:
                    color_print(f"Scanning [{idx}/{len(urls)}]: {url}", "info")
                result = scan_url(url, payloads, args)
                if result:
                    findings.extend(result)

        elif args.file:
            color_print(f"Loading targets from {args.file}", "info")
            if not os.path.exists(args.file):
                color_print(f"File not found: {args.file}", "error")
                sys.exit(1)
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            color_print(f"Loaded {len(urls)} targets", "success")
            for idx, url in enumerate(urls, 1):
                if not args.quiet:
                    color_print(f"Scanning [{idx}/{len(urls)}]: {url}", "info")
                result = scan_url(url, payloads, args)
                if result:
                    findings.extend(result)

        elif args.url:
            result = scan_url(args.url, payloads, args)
            if result:
                findings.extend(result)

        elapsed = time.time() - start_time

        if findings:
            color_print(f"\n{'='*60}", "header")
            color_print(f"SCAN COMPLETE - {len(findings)} XSS vulnerabilities found", "critical")
            color_print(f"Time taken: {elapsed:.2f} seconds", "info")
            color_print(f"{'='*60}", "header")
        else:
            color_print(f"\nScan completed in {elapsed:.2f} seconds. No XSS vulnerabilities detected.", "info")

        if args.output and findings:
            ext = os.path.splitext(args.output)[1].lower()
            format_map = {'.json': 'json', '.html': 'html', '.txt': 'txt'}
            fmt = format_map.get(ext, 'json')
            save_report(findings, args.output, fmt)
            color_print(f"Report saved to {args.output} (format: {fmt})", "success")

    except KeyboardInterrupt:
        color_print("\nScan interrupted by user", "warning")
        sys.exit(130)
    except Exception as e:
        color_print(f"Fatal error: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()