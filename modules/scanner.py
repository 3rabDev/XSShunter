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

import urllib.parse
import re
import concurrent.futures
from colorama import Fore
from modules.utils import get_session, detect_waf
from modules.dom_analyzer import analyze_dom

def scan_url(url, payloads, args):
    findings = []
    session = get_session(args.cookie)
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    post_data = args.data if args.data else None


    has_params = bool(params) or ('=' in parsed.query)
    
    if not has_params and not post_data:
        print(f"{Fore.YELLOW}[*] No parameters or POST data in {url}")
        return findings

    print(f"{Fore.BLUE}[*] Testing {url} with {len(payloads)} payloads")

    if args.waf:
        try:
            resp = session.get(url, timeout=10)
            waf = detect_waf(resp)
            if waf:
                print(f"{Fore.RED}[!] WAF detected: {waf}")
        except:
            pass

    if args.dom:
        dom_result = analyze_dom(url, session)
        if dom_result:
            print(f"{Fore.GREEN}[+] DOM XSS potential: {len(dom_result)} sinks")

    def test_payload(param, payload, test_url=None, post_data_dict=None):
        nonlocal findings
        try:
            if post_data_dict:
                test_data = post_data_dict.copy()
                if param in test_data:
                    test_data[param] = payload
                response = session.post(url, data=test_data, timeout=10)
                response_text = response.text
                request_url = url
            else:
                response = session.get(test_url, timeout=10)
                response_text = response.text
                request_url = test_url

            if payload not in response_text:
                return

            if payload.replace('<', '&lt;') in response_text:
                return

            context = detect_context(response_text, payload)
            finding = {
                "url": url,
                "parameter": param,
                "payload": payload,
                "context": context,
                "evidence": response_text[:500],
                "type": "Reflected XSS" if not post_data_dict else "POST XSS",
                "request_url": request_url
            }
            findings.append(finding)
            print(f"{Fore.RED}[!] XSS Found! {url} - Parameter: {param} [{context}]")
            print(f"{Fore.YELLOW}    Payload: {payload[:80]}")

            if args.headless:
                from modules.headless import verify_xss
                if verify_xss(request_url, payload):
                    print(f"{Fore.GREEN}[✓] Verified with headless browser")

            if args.blind:
                print(f"{Fore.CYAN}[*] Blind XSS payload sent (check callback)")

        except Exception as e:
            print(f"{Fore.RED}[-] Error on {param}: {str(e)[:50]}")

    def detect_context(text, payload):
        escaped = re.escape(payload)
        if re.search(f'<script[^>]*>{escaped}', text, re.IGNORECASE):
            return 'script block'
        elif re.search(f'on\\w+\\s*=\\s*["\']?[^"\']*{escaped}', text, re.IGNORECASE):
            return 'event handler'
        elif re.search(f'href\\s*=\\s*["\']?javascript:{escaped}', text, re.IGNORECASE):
            return 'javascript uri'
        elif re.search(f'<\\w+[^>]*{escaped}[^>]*>', text, re.IGNORECASE):
            return 'tag attribute'
        else:
            return 'plain text'

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads if hasattr(args, 'threads') else 10) as executor:
        futures = []
        if post_data:
            try:
                import json
                post_dict = json.loads(post_data)
            except:
                post_dict = dict(x.split('=',1) for x in post_data.split('&') if '=' in x)
            for param in post_dict.keys():
                for payload in payloads:
                    futures.append(executor.submit(test_payload, param, payload, None, post_dict))
        else:
            for param in params.keys():
                for payload in payloads:
                    new_params = params.copy()
                    new_params[param] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    futures.append(executor.submit(test_payload, param, payload, test_url, None))

        for future in concurrent.futures.as_completed(futures):
            future.result()

    return findings