#!/usr/bin/env python3

import logging
import re
from typing import Dict, List

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class DOMAnalyzer:
    def __init__(self, session, use_headless: bool = False):
        self.session = session
        self.use_headless = use_headless
        self.findings: List[Dict[str, str]] = []

    def analyze(self, url: str) -> Dict[str, object]:
        try:
            response = self.session.get(url, timeout=15)
        except Exception:
            logger.debug("DOM analysis request failed for %s", url, exc_info=True)
            return self._report()
        soup = BeautifulSoup(response.text, "html.parser")
        self._scan_inline_handlers(soup, url)
        self._scan_script_blocks(soup, url)
        self._scan_javascript_urls(soup, url)
        self._scan_forms(soup, url)
        self._scan_meta_refresh(soup, url)
        return self._report()

    def _append(self, url: str, parameter: str, payload: str, context: str, finding_type: str, confidence: str = "medium") -> None:
        self.findings.append(
            {
                "url": url,
                "parameter": parameter,
                "payload": payload[:400],
                "context": context,
                "type": finding_type,
                "confidence": confidence,  # low, medium, high
                "verified": False,
            }
        )

    def _scan_inline_handlers(self, soup: BeautifulSoup, url: str) -> None:
        """Scan for dangerous inline event handlers."""
        dangerous = {
            "onload": "high",
            "onerror": "high",
            "onclick": "medium",
            "onmouseover": "medium",
            "onfocus": "medium",
            "oninput": "medium",
            "onchange": "low",
            "onsubmit": "medium",
            "ondrag": "low",
            "ondrop": "low",
            "onkeyup": "low",
            "onkeydown": "low",
        }
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                attr_lower = attr.lower()
                if attr_lower in dangerous:
                    confidence = dangerous[attr_lower]
                    self._append(url, attr_lower, str(value), tag.name, "DOM Event Handler", confidence)

    def _scan_script_blocks(self, soup: BeautifulSoup, url: str) -> None:
        """Scan for DOM source-to-sink flows and framework-specific sinks."""
        # DOM sources - user-controllable data
        sources = {
            "location": "high",
            "location.search": "high",
            "location.hash": "high",
            "document.cookie": "medium",
            "document.URL": "high",
            "document.referrer": "medium",
            "window.name": "high",
            "localStorage": "medium",
            "sessionStorage": "medium",
            "window.location": "high",
            "history.state": "low",
        }
        
        # Dangerous sinks - vulnerable to XSS
        sinks = {
            "innerHTML": "high",
            "outerHTML": "high",
            "document.write": "high",
            "document.writeln": "high",
            "eval": "high",
            "setTimeout": "medium",
            "setInterval": "medium",
            "insertAdjacentHTML": "high",
            "createContextualFragment": "high",
            "appendChild": "low",
            "insertBefore": "low",
        }
        
        # Framework-specific sinks with confidence scoring
        framework_patterns = [
            (r"dangerouslySetInnerHTML\s*=", "React Sink", "high"),
            (r"v-html\s*=", "Vue Sink", "high"),
            (r"ng-bind-html", "Angular Sink", "high"),
            (r"\.html\s*\(", "jQuery Sink", "high"),
            (r"\$\(.*\)\.html\(", "jQuery DOM manipulation", "high"),
            (r"\[ngInnerHTML\]", "Angular Inner HTML", "high"),
            (r"AngularJS", "Angular Detection", "medium"),
            (r"Vue\.prototype", "Vue Detection", "medium"),
        ]
        
        for script in soup.find_all("script"):
            code = script.string or script.get_text() or ""
            if not code.strip():
                continue
            
            # Check for source-to-sink flows
            matched_sources = [(src, sources[src]) for src in sources if src in code]
            matched_sinks = [(sink, sinks[sink]) for sink in sinks if sink in code]
            
            if matched_sources and matched_sinks:
                # Calculate confidence based on source and sink severity
                source_conf = max([conf for _, conf in matched_sources], key=lambda x: ["low", "medium", "high"].index(x))
                sink_conf = max([conf for _, conf in matched_sinks], key=lambda x: ["low", "medium", "high"].index(x))
                
                # Combine confidences
                confidence_map = {
                    ("high", "high"): "high",
                    ("high", "medium"): "high",
                    ("medium", "high"): "high",
                    ("medium", "medium"): "medium",
                    ("low", "high"): "medium",
                    ("high", "low"): "medium",
                    ("medium", "low"): "low",
                    ("low", "low"): "low",
                }
                final_confidence = confidence_map.get((source_conf, sink_conf), "medium")
                
                self._append(
                    url,
                    ",".join([s for s, _ in matched_sources]),
                    code[:400],
                    ",".join([sink for sink, _ in matched_sinks]),
                    "DOM Source to Sink",
                    final_confidence
                )
            
            # Check framework patterns
            for pattern, finding_type, confidence in framework_patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    self._append(url, "script", code[:400], "script block", finding_type, confidence)

    def _scan_javascript_urls(self, soup: BeautifulSoup, url: str) -> None:
        """Scan for JavaScript protocol URLs."""
        for tag in soup.find_all(href=True):
            href = str(tag.get("href", ""))
            if href.lower().startswith("javascript:"):
                # JavaScript URLs are always high confidence
                self._append(url, "href", href, tag.name, "JavaScript URL", "high")
        
        for tag in soup.find_all(src=True):
            src = str(tag.get("src", ""))
            if src.lower().startswith("javascript:"):
                self._append(url, "src", src, tag.name, "JavaScript URL", "high")

    def _scan_forms(self, soup: BeautifulSoup, url: str) -> None:
        """Scan for form input surfaces - potential attack vectors."""
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            names = [field.get("name") for field in form.find_all(["input", "textarea", "select"]) if field.get("name")]
            if names:
                # Forms are medium confidence - they're attack vectors but not vulnerabilities by themselves
                self._append(url, ",".join(names), method, "form", "Input Surface", "medium")

    def _scan_meta_refresh(self, soup: BeautifulSoup, url: str) -> None:
        """Scan for meta refresh with JavaScript protocol."""
        for meta in soup.find_all("meta"):
            http_equiv = str(meta.get("http-equiv", "")).lower()
            content = str(meta.get("content", ""))
            if http_equiv == "refresh" and "javascript:" in content.lower():
                # Meta refresh with JavaScript is high confidence
                self._append(url, "content", content, "meta", "Meta Refresh JavaScript", "high")

    def _report(self) -> Dict[str, object]:
        """Generate analysis report with confidence scoring."""
        high_conf = sum(1 for f in self.findings if f.get("confidence") == "high")
        medium_conf = sum(1 for f in self.findings if f.get("confidence") == "medium")
        low_conf = sum(1 for f in self.findings if f.get("confidence") == "low")
        
        return {
            "findings": self.findings,
            "count": len(self.findings),
            "confidence_breakdown": {
                "high": high_conf,
                "medium": medium_conf,
                "low": low_conf,
            },
            "summary": f"{high_conf} high, {medium_conf} medium, {low_conf} low confidence findings"
        }


def analyze_dom(url: str, session, headless: bool = False) -> Dict[str, object]:
    return DOMAnalyzer(session, headless).analyze(url)
