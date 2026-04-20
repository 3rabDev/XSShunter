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

from bs4 import BeautifulSoup
import re
import json
import hashlib
import logging
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse, parse_qs, urljoin
from collections import defaultdict
import ast

logger = logging.getLogger(__name__)

class DOMAnalyzer:
    def __init__(self, session, use_headless=False):
        self.session = session
        self.use_headless = use_headless
        self.results = []
        self.score = 0
        self.csp = None
        self.trusted_types = False
        self.iframe_urls = []
        self.js_ast_cache = {}

    def analyze(self, url, depth=0):
        if depth > 2:
            return self._generate_report()
        try:
            response = self.session.get(url, timeout=15)
            self._check_csp(response.headers.get('Content-Security-Policy', ''))
            soup = BeautifulSoup(response.text, 'html.parser')
            self._analyze_html(soup)
            self._analyze_js_blocks(soup)
            self._analyze_attributes(soup)
            self._analyze_forms(soup)
            self._analyze_meta_tags(soup)
            self._analyze_iframes(soup, url, depth)
            if self.use_headless:
                self._dynamic_analysis(url)
            return self._generate_report()
        except Exception as e:
            logger.error(f"DOM analysis error for {url}: {e}")
            return self._generate_report()

    def _check_csp(self, csp_header):
        self.csp = csp_header
        if csp_header and 'trusted-types' in csp_header.lower():
            self.trusted_types = True

    def _analyze_html(self, soup):
        dangerous_patterns = [
            (r'<script[^>]*src\s*=\s*["\'](?:data:|javascript:)', 'Dangerous script src', 'High'),
            (r'<iframe[^>]*src\s*=\s*["\'](?:javascript:|data:)', 'Dangerous iframe src', 'High'),
            (r'<object[^>]*data\s*=\s*["\'](?:javascript:|data:)', 'Dangerous object data', 'High'),
            (r'<embed[^>]*src\s*=\s*["\'](?:javascript:|data:)', 'Dangerous embed src', 'High'),
            (r'<link[^>]*href\s*=\s*["\'](?:javascript:|data:)', 'Dangerous link href', 'Medium'),
            (r'<base[^>]*href\s*=\s*["\'][^"\']*["\']', 'Base tag hijacking potential', 'High'),
            (r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\'][^"\']*url\s*=', 'Meta refresh XSS', 'Medium'),
            (r'<math[^>]*<[^>]*alert', 'SVG/MathML XSS vector', 'Critical'),
            (r'<isindex[^>]*action\s*=', 'Isindex XSS', 'High'),
            (r'<style[^>]*>\s*expression\(', 'CSS expression XSS (IE)', 'High')
        ]
        for pattern, desc, severity in dangerous_patterns:
            for match in re.finditer(pattern, str(soup), re.IGNORECASE):
                self._add_finding('html_injection', desc, match.group(0)[:200], severity)

    def _analyze_js_blocks(self, soup):
        sources = {
            'location': ['location', 'location.href', 'location.search', 'location.hash', 'location.pathname', 'location.protocol', 'location.origin'],
            'document': ['document.URL', 'document.documentURI', 'document.baseURI', 'document.referrer', 'document.cookie', 'document.domain'],
            'window': ['window.name', 'window.location', 'window.documentURI', 'window.opener'],
            'navigation': ['history.pushState', 'history.replaceState', 'history.state'],
            'storage': ['localStorage', 'sessionStorage', 'sessionStorage.getItem', 'localStorage.getItem', 'localStorage.setItem'],
            'dom_refs': ['document.getElementById', 'document.getElementsByClassName', 'document.querySelector', 'document.querySelectorAll', 'document.getElementsByName'],
            'url_params': ['URLSearchParams', 'new URL(location.href).searchParams', 'decodeURIComponent', 'decodeURI'],
            'web_apis': ['fetch', 'XMLHttpRequest', 'WebSocket', 'postMessage', 'MessageChannel', 'BroadcastChannel'],
            'input_elements': ['value', 'innerText', 'textContent', 'data', 'responseText', 'responseXML'],
            'reflection': ['document.forms', 'document.images', 'document.links', 'document.anchors', 'document.embeds']
        }
        sinks = {
            'code_exec': ['eval', 'Function', 'setTimeout', 'setInterval', 'setImmediate', 'execScript', 'importScripts', 'requestAnimationFrame', 'setImmediate'],
            'dom_write': ['document.write', 'document.writeln', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'createContextualFragment', 'DOMParser.parseFromString'],
            'dom_modify': ['appendChild', 'insertBefore', 'replaceChild', 'setAttribute', 'setAttributeNode', 'setAttributeNS', 'setProperty', 'replaceChildren'],
            'navigation_sinks': ['location.assign', 'location.replace', 'location.href', 'window.open', 'location.reload', 'navigate'],
            'script_insert': ['createElement', 'src', 'textContent', 'innerText', 'insertBefore', 'insertAdjacentElement'],
            'event_creation': ['addEventListener', 'attachEvent', 'onclick', 'onerror', 'onload', 'onmouseover', 'onfocus', 'oninput'],
            'websocket_sinks': ['send', 'postMessage'],
            'crypto_sinks': ['crypto.generateCRMFRequest', 'crypto.subtle.encrypt', 'crypto.subtle.decrypt']
        }
        for script in soup.find_all('script'):
            if not script.string:
                continue
            code = script.string
            self._analyze_ast(code)
            for src_cat, src_list in sources.items():
                for src in src_list:
                    if re.search(r'\b' + re.escape(src) + r'\b', code):
                        for sink_cat, sink_list in sinks.items():
                            for sink in sink_list:
                                if re.search(r'\b' + re.escape(sink) + r'\s*\(', code):
                                    self._add_finding('dom_xss_flow', f'Source: {src} → Sink: {sink}',
                                                      f'...{code[max(0, code.find(src)-50):code.find(sink)+100]}...', 'Critical')
                                    break
            for sink_cat, sink_list in sinks.items():
                for sink in sink_list:
                    pattern = r'\b' + re.escape(sink) + r'\s*\(\s*(?:[^)]*[\'"]\s*\+\s*[^\'"]+[\'"]\s*|.*?[\'"]\s*\+\s*.*?)\)'
                    for match in re.finditer(pattern, code, re.DOTALL):
                        self._add_finding('dynamic_sink_call', f'Dynamic argument to {sink}', match.group(0)[:200], 'High')
            js_vars = {}
            var_assign = re.findall(r'var\s+(\w+)\s*=\s*([^;]+);', code)
            for var, val in var_assign:
                js_vars[var] = val
            for var, val in js_vars.items():
                if re.search(r'(?:document\.|location\.|window\.)', val):
                    for sink_cat, sink_list in sinks.items():
                        for sink in sink_list:
                            if re.search(r'\b' + re.escape(sink) + r'\s*\(\s*' + var, code):
                                self._add_finding('indirect_flow', f'Variable {var} (tainted) passed to {sink}', f'{var}={val}', 'High')
        self._analyze_angular(soup)
        self._analyze_vue(soup)
        self._analyze_react(soup)
        self._analyze_jquery(soup)

    def _analyze_ast(self, code):
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    if func_name in ['eval', 'Function', 'setTimeout', 'setInterval']:
                        self._add_finding('ast_code_exec', f'AST detected {func_name} call', ast.unparse(node)[:200], 'Critical')
                elif isinstance(node, ast.Assign):
                    if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                        self._add_finding('ast_string_concat', 'String concatenation may lead to injection', ast.unparse(node)[:200], 'Medium')
        except SyntaxError:
            logger.debug(f"Failed to parse code block for AST analysis")
        except Exception as e:
            logger.debug(f"AST analysis error: {e}")
            pass

    def _analyze_angular(self, soup):
        angular_patterns = [
            (r'ng-bind-html\s*=\s*["\']([^"\']+)["\']', 'ng-bind-html with expression', 'High'),
            (r'ng-include\s*=\s*["\']([^"\']+)["\']', 'ng-include XSS', 'High'),
            (r'{{.*?(?:alert|prompt|confirm|eval).*?}}', 'Angular expression injection', 'Critical'),
            (r'\[innerHTML\]\s*=\s*["\']([^"\']+)["\']', 'Angular innerHTML binding', 'High'),
            (r'ng-src\s*=\s*["\']([^"\']+)["\']', 'Angular src injection', 'Medium'),
            (r'ng-href\s*=\s*["\']([^"\']+)["\']', 'Angular href injection', 'Medium')
        ]
        for pattern, desc, severity in angular_patterns:
            for match in re.finditer(pattern, str(soup), re.IGNORECASE):
                self._add_finding('angular_xss', desc, match.group(0)[:200], severity)

    def _analyze_vue(self, soup):
        vue_patterns = [
            (r'v-html\s*=\s*["\']([^"\']+)["\']', 'Vue v-html XSS', 'Critical'),
            (r'v-bind:innerHTML\s*=\s*["\']([^"\']+)["\']', 'Vue bind innerHTML', 'High'),
            (r'{{.*?(?:alert|prompt|confirm).*?}}', 'Vue template injection', 'High'),
            (r':src\s*=\s*["\']([^"\']+)["\']', 'Vue dynamic src', 'Medium')
        ]
        for pattern, desc, severity in vue_patterns:
            for match in re.finditer(pattern, str(soup), re.IGNORECASE):
                self._add_finding('vue_xss', desc, match.group(0)[:200], severity)

    def _analyze_react(self, soup):
        react_patterns = [
            (r'dangerouslySetInnerHTML\s*=\s*{{', 'React dangerouslySetInnerHTML', 'Critical'),
            (r'innerHTML\s*:\s*["\'][^"\']+["\']', 'React innerHTML assignment', 'High'),
            (r'<script[^>]*>.*?<\/script>', 'Script tag in JSX', 'High')
        ]
        for pattern, desc, severity in react_patterns:
            for match in re.finditer(pattern, str(soup), re.IGNORECASE):
                self._add_finding('react_xss', desc, match.group(0)[:200], severity)

    def _analyze_jquery(self, soup):
        jquery_patterns = [
            (r'\$\([\'"].*?[\'"]\)\.html\(', 'jQuery .html() injection', 'High'),
            (r'\$\([\'"].*?[\'"]\)\.append\(', 'jQuery .append() injection', 'High'),
            (r'\$\([\'"].*?[\'"]\)\.prepend\(', 'jQuery .prepend() injection', 'High'),
            (r'\$\([\'"].*?[\'"]\)\.after\(', 'jQuery .after() injection', 'Medium'),
            (r'\$\([\'"].*?[\'"]\)\.before\(', 'jQuery .before() injection', 'Medium'),
            (r'\$\.get\([^,]*,\s*function', 'jQuery AJAX callback may inject', 'Medium'),
            (r'\$\.post\([^,]*,\s*function', 'jQuery AJAX callback may inject', 'Medium')
        ]
        for pattern, desc, severity in jquery_patterns:
            for match in re.finditer(pattern, str(soup), re.IGNORECASE):
                self._add_finding('jquery_xss', desc, match.group(0)[:200], severity)

    def _analyze_attributes(self, soup):
        dangerous_attrs = {
            'onload': 'High', 'onerror': 'High', 'onclick': 'Medium', 'onmouseover': 'Low',
            'onfocus': 'Medium', 'oninput': 'Medium', 'onchange': 'Medium', 'onsubmit': 'Medium',
            'onreset': 'Low', 'onselect': 'Low', 'onblur': 'Low', 'onkeydown': 'Low',
            'onkeypress': 'Low', 'onkeyup': 'Low', 'oncontextmenu': 'Medium', 'ondblclick': 'Low',
            'onmousedown': 'Low', 'onmousemove': 'Low', 'onmouseout': 'Low', 'onmouseup': 'Low',
            'onwheel': 'Low', 'onauxclick': 'Low', 'onpointerdown': 'Low', 'onpointermove': 'Low',
            'onpointerup': 'Low', 'onpointercancel': 'Low'
        }
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                if attr in dangerous_attrs and value:
                    if re.search(r'alert|prompt|confirm|eval|fetch|location\.href|document\.cookie', value, re.IGNORECASE):
                        self._add_finding('inline_event_handler', f'{tag.name}:{attr}', value[:150], dangerous_attrs[attr])
                elif attr == 'href' and value.startswith('javascript:'):
                    self._add_finding('javascript_uri', f'{tag.name}:href', value[:150], 'High')
                elif attr == 'src' and value.startswith('javascript:'):
                    self._add_finding('javascript_src', f'{tag.name}:src', value[:150], 'High')
                elif attr == 'action' and 'javascript:' in value:
                    self._add_finding('form_action_xss', f'{tag.name}:action', value[:150], 'Medium')
                elif attr == 'style' and re.search(r'expression\(|url\(', value, re.IGNORECASE):
                    self._add_finding('css_expression_xss', f'{tag.name}:style', value[:150], 'High')
                elif attr == 'data' and value.startswith('javascript:'):
                    self._add_finding('object_data_xss', f'{tag.name}:data', value[:150], 'High')
                elif attr == 'formaction' and 'javascript:' in value:
                    self._add_finding('formaction_xss', f'{tag.name}:formaction', value[:150], 'High')

    def _analyze_forms(self, soup):
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                if inp.get('value') and len(inp['value']) > 10:
                    if re.search(r'<[^>]*>|alert|prompt|confirm|javascript:', inp['value'], re.IGNORECASE):
                        self._add_finding('stored_xss_candidate', f'Form input {inp.get("name")}', inp['value'][:150], 'Medium')
                if inp.get('type') == 'hidden' and inp.get('value'):
                    self._add_finding('hidden_field_potential', f'Hidden {inp.get("name")}', inp['value'][:100], 'Low')
                if inp.get('type') == 'url' and not inp.get('pattern'):
                    self._add_finding('unsafe_url_input', 'URL input without pattern validation', inp.get('name', 'unknown'), 'Medium')

    def _analyze_meta_tags(self, soup):
        meta_refresh = soup.find('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'refresh'})
        if meta_refresh and meta_refresh.get('content'):
            content = meta_refresh['content']
            if 'url=' in content.lower():
                self._add_finding('meta_refresh_xss', 'Meta refresh with URL', content, 'Medium')
        csp_meta = soup.find('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'content-security-policy'})
        if csp_meta and csp_meta.get('content'):
            self.csp = csp_meta['content']
            if 'unsafe-inline' in self.csp:
                self._add_finding('csp_unsafe_inline', 'CSP allows unsafe-inline', self.csp[:100], 'Medium')
            if 'unsafe-eval' in self.csp:
                self._add_finding('csp_unsafe_eval', 'CSP allows unsafe-eval', self.csp[:100], 'Medium')
            if '*' in self.csp:
                self._add_finding('csp_wildcard', 'CSP contains wildcard (*)', self.csp[:100], 'High')
        xss_protection = soup.find('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'x-xss-protection'})
        if xss_protection and xss_protection.get('content') == '0':
            self._add_finding('xss_protection_disabled', 'X-XSS-Protection disabled', '0', 'Low')

    def _analyze_iframes(self, soup, base_url, depth):
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src')
            if src:
                full_url = urljoin(base_url, src)
                self.iframe_urls.append(full_url)
                if depth < 2:
                    self.analyze(full_url, depth+1)

    def _dynamic_analysis(self, url):
        try:
            from modules.headless import verify_xss
            test_payload = '<img src=x onerror=this.setAttribute("data-xss","detected")>'
            if verify_xss(url + ('' if '?' in url else '?') + f'q={test_payload}', test_payload):
                self._add_finding('dynamic_confirmed_xss', 'Headless browser confirmed XSS execution', test_payload, 'Critical')
        except ImportError:
            logger.debug("Headless module not available for dynamic analysis")
        except Exception as e:
            logger.debug(f"Dynamic analysis error: {e}")

    def _add_finding(self, finding_type, description, context, severity):
        finding = {
            'type': finding_type,
            'description': description,
            'context': context.strip(),
            'severity': severity,
            'score': self._severity_score(severity)
        }
        self.results.append(finding)
        self.score += finding['score']

    def _severity_score(self, severity):
        return {'Low': 1, 'Medium': 3, 'High': 7, 'Critical': 10}.get(severity, 0)

    def _generate_report(self):
        if not self.results:
            return None
        return {
            'total_findings': len(self.results),
            'risk_score': self.score,
            'csp': self.csp,
            'trusted_types': self.trusted_types,
            'iframe_urls': self.iframe_urls,
            'findings': self.results,
            'recommendations': self._get_recommendations()
        }

    def _get_recommendations(self):
        recs = []
        if self.trusted_types:
            recs.append('Trusted Types enabled - good, but ensure policies are strict.')
        if self.csp and 'unsafe-inline' in self.csp:
            recs.append('Remove unsafe-inline from CSP and use nonces/hashes.')
        if any(f['type'] == 'inline_event_handler' for f in self.results):
            recs.append('Avoid inline event handlers. Use addEventListener with strict CSP.')
        if any(f['type'] == 'dom_xss_flow' for f in self.results):
            recs.append('Sanitize all untrusted data before passing to DOM sinks (use DOMPurify).')
        if any(f['type'] == 'angular_xss' for f in self.results):
            recs.append('Use $sce.trustAsHtml or strict context escaping in Angular.')
        if any(f['type'] == 'vue_xss' for f in self.results):
            recs.append('Avoid v-html with user input. Use sanitizers.')
        if any(f['type'] == 'react_xss' for f in self.results):
            recs.append('Do not use dangerouslySetInnerHTML with unsanitized data.')
        if any(f['type'] == 'jquery_xss' for f in self.results):
            recs.append('Avoid .html(), .append(), etc. with user input. Use .text() or DOMPurify.')
        return recs

def analyze_dom(url, session, headless=False):
    analyzer = DOMAnalyzer(session, headless)
    return analyzer.analyze(url)