#!/usr/bin/env python3

import logging
import re

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class DOMAnalyzer:
    def __init__(self, session, use_headless=False):
        self.session = session
        self.use_headless = use_headless
        self.findings = []

    def analyze(self, url):
        try:
            response = self.session.get(url, timeout=15)
        except Exception:
            logger.debug("DOM analysis request failed for %s", url, exc_info=True)
            return self._report()
        soup = BeautifulSoup(response.text, "html.parser")
        self._scan_inline_handlers(soup, url)
        self._scan_script_blocks(soup, url)
        self._scan_forms(soup, url)
        return self._report()

    def _scan_inline_handlers(self, soup, url):
        dangerous = {"onload", "onerror", "onclick", "onmouseover", "onfocus", "oninput"}
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.lower() in dangerous:
                    self.findings.append(
                        {
                            "url": url,
                            "parameter": attr.lower(),
                            "payload": str(value),
                            "context": tag.name,
                            "type": "DOM Event Handler",
                            "verified": False,
                        }
                    )

    def _scan_script_blocks(self, soup, url):
        sources = [
            "location",
            "location.search",
            "location.hash",
            "document.cookie",
            "document.URL",
            "document.referrer",
            "window.name",
        ]
        sinks = [
            "innerHTML",
            "outerHTML",
            "document.write",
            "document.writeln",
            "eval",
            "setTimeout",
            "setInterval",
            "insertAdjacentHTML",
        ]
        for script in soup.find_all("script"):
            code = script.string or script.get_text() or ""
            if not code.strip():
                continue
            matched_sources = [source for source in sources if source in code]
            matched_sinks = [sink for sink in sinks if sink in code]
            if matched_sources and matched_sinks:
                self.findings.append(
                    {
                        "url": url,
                        "parameter": ",".join(matched_sources),
                        "payload": code[:200],
                        "context": ",".join(matched_sinks),
                        "type": "DOM Source to Sink",
                        "verified": False,
                    }
                )
            if re.search(r"dangerouslySetInnerHTML|v-html|ng-bind-html|\.html\s*\(", code):
                self.findings.append(
                    {
                        "url": url,
                        "parameter": "script",
                        "payload": code[:200],
                        "context": "framework sink",
                        "type": "Framework DOM Sink",
                        "verified": False,
                    }
                )

    def _scan_forms(self, soup, url):
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            names = [field.get("name") for field in form.find_all(["input", "textarea", "select"]) if field.get("name")]
            if names:
                self.findings.append(
                    {
                        "url": url,
                        "parameter": ",".join(names),
                        "payload": method,
                        "context": "form",
                        "type": "Input Surface",
                        "verified": False,
                    }
                )

    def _report(self):
        return {
            "findings": self.findings,
            "count": len(self.findings),
        }


def analyze_dom(url, session, headless=False):
    return DOMAnalyzer(session, headless).analyze(url)
