#!/usr/bin/env python3

import logging
import queue
import threading
from typing import Dict, List, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from modules.headless import check_chrome_setup
from modules.utils import color_print, get_session, normalize_url, parse_cookie_string, random_delay

logger = logging.getLogger(__name__)

# Try to import Selenium for JavaScript rendering
try:
    from selenium import webdriver
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    try:
        from webdriver_manager.chrome import ChromeDriverManager
    except Exception:
        ChromeDriverManager = None
    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False
    webdriver = None
    TimeoutException = Exception
    WebDriverException = Exception
    Options = None
    Service = None
    WebDriverWait = None
    ChromeDriverManager = None


class SmartCrawler:
    def __init__(
        self,
        start_url: str,
        threads: int = 10,
        depth: int = 2,
        same_domain: bool = True,
        delay: float = 0.1,
        headers: Dict[str, str] = None,
        cookie: str = None,
        proxy: str = None,
        timeout: int = 15,
    ):
        self.start_url = normalize_url(start_url)
        self.threads = max(1, min(int(threads), 50))
        self.max_depth = max(1, min(int(depth), 5))
        self.same_domain = bool(same_domain)
        self.delay = max(0.0, float(delay))
        self.timeout = max(1, int(timeout))
        self.headers = headers or {}
        self.cookie = cookie
        self.proxy = proxy
        self.domain = urlparse(self.start_url).netloc
        self.visited: Set[str] = set()
        self.discovered: Set[str] = {self.start_url}
        self.pending: Set[str] = {self.start_url}
        self.lock = threading.Lock()
        self.session = get_session(
            cookie=self.cookie,
            proxy=self.proxy,
            timeout=self.timeout,
            headers=self.headers,
            user_agent=self.headers.get("User-Agent"),
        )
        cookies = parse_cookie_string(cookie)
        if cookies:
            self.session.cookies.update(cookies)

    def _normalize(self, url: str) -> str:
        if not url:
            return ""
        candidate = normalize_url(url.split("#", 1)[0].strip())
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"}:
            return ""
        path = parsed.path or "/"
        query = urlencode(parse_qs(parsed.query, keep_blank_values=True), doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, path.rstrip("/") or "/", "", query, ""))

    def _valid(self, url: str) -> bool:
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
            ".rar",
            ".mp4",
            ".mp3",
            ".woff",
            ".woff2",
            ".ttf",
            ".css",
        )
        return not parsed.path.lower().endswith(blocked)

    def _extract(self, html: str, base_url: str) -> Set[str]:
        soup = BeautifulSoup(html, "html.parser")
        urls: Set[str] = set()
        for tag in soup.find_all(["a", "link", "area"], href=True):
            candidate = self._normalize(urljoin(base_url, tag.get("href", "")))
            if self._valid(candidate):
                urls.add(candidate)
        for tag in soup.find_all(["iframe", "frame"], src=True):
            candidate = self._normalize(urljoin(base_url, tag.get("src", "")))
            if self._valid(candidate):
                urls.add(candidate)
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

    def _fetch(self, url: str) -> str:
        random_delay(0.0, self.delay)
        response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        if "text/html" not in response.headers.get("Content-Type", "").lower():
            return ""
        return response.text

    def _worker(self, work_queue: queue.Queue) -> None:
        while True:
            try:
                url, depth = work_queue.get(timeout=0.5)
            except queue.Empty:
                return
            try:
                with self.lock:
                    if url in self.visited:
                        continue
                    self.visited.add(url)
                if depth > self.max_depth:
                    continue
                html = self._fetch(url)
                if not html:
                    continue
                for child in self._extract(html, url):
                    with self.lock:
                        if child in self.visited or child in self.pending:
                            continue
                        self.pending.add(child)
                        self.discovered.add(child)
                    if depth < self.max_depth:
                        work_queue.put((child, depth + 1))
            except Exception:
                logger.debug("Crawler worker failed for %s", url, exc_info=True)
            finally:
                work_queue.task_done()

    def crawl(self) -> List[str]:
        color_print(f"Starting crawl on {self.start_url}", "header")
        work_queue: queue.Queue[Tuple[str, int]] = queue.Queue()
        work_queue.put((self.start_url, 0))
        workers = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self._worker, args=(work_queue,), daemon=True)
            thread.start()
            workers.append(thread)
        work_queue.join()
        for thread in workers:
            thread.join(timeout=0.2)
        results = sorted(self.discovered)
        color_print(f"Crawl finished. Found {len(results)} URLs.", "success")
        return results


def _crawl_with_javascript(
    start_url: str,
    discovered_urls: List[str],
    depth: int = 2,
    same_domain: bool = True,
    delay: float = 0.1,
    timeout: int = 15,
    cookie: str = None,
) -> List[str]:
    if not SELENIUM_AVAILABLE:
        logger.warning("Selenium not available for JavaScript crawling")
        return []
    setup_ok, setup_message = check_chrome_setup()
    if not setup_ok:
        logger.debug("Skipping JavaScript crawling: %s", setup_message)
        color_print("JavaScript crawling skipped: headless browser setup is not ready", "warning")
        return []

    js_urls: Set[str] = set()
    domain = urlparse(start_url).netloc
    url_validator = SmartCrawler(
        start_url=start_url,
        threads=1,
        depth=depth,
        same_domain=same_domain,
        delay=delay,
        cookie=cookie,
        timeout=timeout,
    )

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1440,1024")

    driver = None
    try:
        try:
            driver = webdriver.Chrome(options=options)
        except Exception:
            if ChromeDriverManager:
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=options)
            else:
                raise

        color_print("JavaScript rendering enabled for crawling", "info")
        urls_to_render = discovered_urls[:min(10, len(discovered_urls))]

        for url in urls_to_render:
            try:
                random_delay(delay)
                driver.get(url)
                WebDriverWait(driver, min(timeout // 2, 5)).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
                page_source = driver.page_source
                soup = BeautifulSoup(page_source, "html.parser")

                for link in soup.find_all("a", href=True):
                    href = link.get("href", "")
                    if not href:
                        continue
                    candidate_url = url_validator._normalize(urljoin(url, href))
                    if not url_validator._valid(candidate_url):
                        continue
                    if candidate_url not in discovered_urls:
                        js_urls.add(candidate_url)
                        logger.debug(f"JavaScript: Found URL {candidate_url}")

            except TimeoutException:
                logger.debug(f"Timeout rendering {url}")
            except WebDriverException:
                logger.debug(f"WebDriver error for {url}", exc_info=True)
            except Exception as e:
                logger.debug(f"Error rendering {url}: {e}")

    except WebDriverException as e:
        logger.warning(f"Chrome/WebDriver not available: {e}")
    except Exception as e:
        logger.error(f"JavaScript crawling failed: {e}")
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    return list(js_urls)


def crawl_site(
    start_url: str,
    threads: int = 10,
    depth: int = 2,
    same_domain: bool = True,
    delay: float = 0.1,
    headers: Dict[str, str] = None,
    cookie: str = None,
    proxy: str = None,
    timeout: int = 15,
    use_javascript: bool = False,
) -> List[str]:
    """Crawl a website and return discovered URLs."""
    crawler = SmartCrawler(
        start_url=start_url,
        threads=threads,
        depth=depth,
        same_domain=same_domain,
        delay=delay,
        headers=headers,
        cookie=cookie,
        proxy=proxy,
        timeout=timeout,
    )
    
    urls = crawler.crawl()
    
    # If JavaScript rendering is enabled, extract additional URLs from JS-rendered pages
    if use_javascript:
        js_urls = _crawl_with_javascript(
            start_url=start_url,
            discovered_urls=urls,
            depth=depth,
            same_domain=same_domain,
            delay=delay,
            timeout=timeout,
            cookie=cookie,
        )
        # Merge with existing URLs
        urls = list(set(urls) | set(js_urls))
    
    return urls
