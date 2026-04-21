#!/usr/bin/env python3

import logging
import queue
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from modules.utils import color_print, get_session

logger = logging.getLogger(__name__)
pending_queue = queue.Queue()


class SmartCrawler:
    def __init__(self, start_url, threads=10, depth=2, same_domain=True, delay=0.1, headers=None, cookie=None, timeout=15):
        self.start_url = start_url
        self.threads = max(1, min(threads, 50))
        self.max_depth = max(1, depth)
        self.same_domain = same_domain
        self.delay = max(0.0, delay)
        self.timeout = timeout
        self.headers = headers or {}
        self.cookie = cookie
        self.domain = urlparse(start_url).netloc
        self.visited = set()
        self.discovered = set()
        self.lock = threading.Lock()

    def _normalize(self, url):
        if not url:
            return ""
        candidate = url.split("#", 1)[0].strip()
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"}:
            return ""
        path = parsed.path or "/"
        query = urlencode(parse_qs(parsed.query, keep_blank_values=True), doseq=True)
        normalized = urlunparse((parsed.scheme, parsed.netloc, path.rstrip("/") or "/", "", query, ""))
        return normalized

    def _valid(self, url):
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if self.same_domain and parsed.netloc != self.domain:
            return False
        blocked = (
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".svg",
            ".ico",
            ".pdf",
            ".zip",
            ".gz",
            ".mp4",
            ".mp3",
            ".woff",
            ".woff2",
            ".ttf",
        )
        return not parsed.path.lower().endswith(blocked)

    def _extract(self, html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        urls = set()
        for tag in soup.find_all(["a", "link", "area"], href=True):
            url = self._normalize(urljoin(base_url, tag.get("href", "")))
            if self._valid(url):
                urls.add(url)
        for tag in soup.find_all(["iframe", "frame", "script"], src=True):
            url = self._normalize(urljoin(base_url, tag.get("src", "")))
            if self._valid(url):
                urls.add(url)
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            form_url = self._normalize(urljoin(base_url, action))
            if not self._valid(form_url):
                continue
            urls.add(form_url)
            inputs = {}
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                field_type = (field.get("type") or "").lower()
                if name and field_type not in {"submit", "button", "reset"}:
                    inputs[name] = field.get("value", "")
            if inputs:
                parsed = urlparse(form_url)
                query = urlencode(inputs, doseq=True)
                urls.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, "")))
        return urls

    def _fetch(self, url):
        session = get_session(cookie=self.cookie, timeout=self.timeout, headers=self.headers)
        time.sleep(self.delay)
        response = session.get(url, timeout=self.timeout, allow_redirects=True)
        if "text/html" not in response.headers.get("Content-Type", ""):
            return ""
        return response.text

    def _crawl_one(self, url, depth, pending):
        with self.lock:
            if url in self.visited:
                return
            self.visited.add(url)
        try:
            html = self._fetch(url)
        except Exception:
            logger.debug("Failed to fetch %s", url, exc_info=True)
            return
        if not html:
            return
        children = self._extract(html, url)
        with self.lock:
            for child in children:
                if child not in self.discovered:
                    self.discovered.add(child)
        if depth >= self.max_depth:
            return
        for child in children:
            with self.lock:
                if child in self.visited or child in pending:
                    continue
                pending.add(child)
            pending_queue.put((child, depth + 1))

    def crawl(self):
        global pending_queue
        pending_queue = queue.Queue()
        pending = {self.start_url}
        self.discovered.add(self.start_url)
        pending_queue.put((self.start_url, 0))
        color_print(f"Starting crawl on {self.start_url}", "header")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            active = set()
            while not pending_queue.empty() or active:
                while not pending_queue.empty() and len(active) < self.threads:
                    url, depth = pending_queue.get()
                    future = executor.submit(self._crawl_one, url, depth, pending)
                    active.add(future)
                done, active = wait(active, timeout=0.1, return_when=FIRST_COMPLETED)
                for future in done:
                    future.result()
        results = sorted(self.discovered)
        color_print(f"Crawl finished. Found {len(results)} URLs.", "success")
        return results


def crawl_site(start_url, threads=10, depth=2, same_domain=True, delay=0.1, headers=None, cookie=None, timeout=15):
    crawler = SmartCrawler(
        start_url=start_url,
        threads=threads,
        depth=depth,
        same_domain=same_domain,
        delay=delay,
        headers=headers,
        cookie=cookie,
        timeout=timeout,
    )
    return crawler.crawl()
