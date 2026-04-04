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

import threading
import queue
import time
import urllib.robotparser
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, quote
from collections import deque
from bs4 import BeautifulSoup
import requests
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import get_session, random_delay, color_print

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_OK = True
except:
    SELENIUM_OK = False

class SmartCrawler:
    def __init__(self, start_url, threads=30, depth=4, same_domain=True, delay=0.05, respect_robots=False, user_agent=None, use_js=False, cookies=None, headers=None, timeout=10):
        self.start_url = start_url
        self.threads = min(threads, 150)
        self.max_depth = depth
        self.same_domain = same_domain
        self.delay = delay
        self.respect_robots = respect_robots
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.use_js = use_js and SELENIUM_OK
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.timeout = timeout
        self.visited = set()
        self.visited_lock = threading.Lock()
        self.queue = queue.Queue()
        self.all_urls = set()
        self.domain = urlparse(start_url).netloc
        self.rp = None
        self.driver = None
        if self.respect_robots:
            self._init_robots()
        if self.use_js:
            self._init_selenium()

    def _init_robots(self):
        parsed = urlparse(self.start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            self.rp = urllib.robotparser.RobotFileParser()
            self.rp.set_url(robots_url)
            self.rp.read()
            color_print(f"Robots.txt loaded from {robots_url}", 'info')
        except:
            self.rp = None

    def _init_selenium(self):
        try:
            opts = Options()
            opts.add_argument("--headless")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--window-size=1920,1080")
            opts.add_argument(f"user-agent={self.user_agent}")
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=opts)
            if self.cookies:
                for name, value in self.cookies.items():
                    self.driver.add_cookie({'name': name, 'value': value})
            color_print("JS rendering enabled", 'success')
        except Exception as e:
            color_print(f"Selenium failed: {e}", 'error')
            self.use_js = False

    def _can_fetch(self, url):
        if not self.rp:
            return True
        return self.rp.can_fetch(self.user_agent, url)

    def _normalize_url(self, url):
        if not url:
            return ''
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'http://' + url.lstrip('/')
        url = url.split('#')[0]
        if url.endswith('/') and not parse_qs(parsed.query):
            url = url[:-1]
        return url

    def _is_valid(self, url):
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return False
        if self.same_domain and parsed.netloc != self.domain:
            return False
        if self.respect_robots and not self._can_fetch(url):
            return False
        blacklist = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.mp4', '.mp3', '.webm', 
                     '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.exe', '.dmg', '.iso', '.bin', 
                     '.woff', '.woff2', '.ttf', '.eot', '.mpg', '.avi', '.mov', '.flv', '.wmv')
        if url.lower().endswith(blacklist):
            return False
        return True

    def _extract_from_html(self, html, base_url):
        links = set()
        try:
            soup = BeautifulSoup(html, 'lxml')
            for tag in soup.find_all(['a', 'link', 'area'], href=True):
                href = tag['href']
                if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                    continue
                full = urljoin(base_url, href)
                full = self._normalize_url(full)
                if self._is_valid(full):
                    links.add(full)
            for tag in soup.find_all(['iframe', 'frame', 'embed'], src=True):
                src = tag['src']
                full = urljoin(base_url, src)
                full = self._normalize_url(full)
                if self._is_valid(full):
                    links.add(full)
            for tag in soup.find_all('form', action=True):
                action = tag['action']
                full = urljoin(base_url, action)
                full = self._normalize_url(full)
                if self._is_valid(full):
                    links.add(full)
                    inputs = {}
                    for inp in tag.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name')
                        if name and inp.get('type') != 'submit' and inp.get('type') != 'button':
                            inputs[name] = ''
                    if inputs:
                        parsed = urlparse(full)
                        query = '&'.join(f"{k}={v}" for k, v in inputs.items())
                        new_q = parsed.query + ('&' + query if parsed.query else query)
                        full_with_params = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                        links.add(full_with_params)
            for tag in soup.find_all(attrs={'data-href': True}):
                val = tag['data-href']
                full = urljoin(base_url, val)
                full = self._normalize_url(full)
                if self._is_valid(full):
                    links.add(full)
            for tag in soup.find_all(attrs={'data-url': True}):
                val = tag['data-url']
                full = urljoin(base_url, val)
                full = self._normalize_url(full)
                if self._is_valid(full):
                    links.add(full)
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    found = re.findall(r'(?:https?://[^\s\'"]+|\/[^\s\'"]+\.(?:php|asp|aspx|jsp|html|htm|js|json|xml))', script.string)
                    for f in found:
                        full = urljoin(base_url, f)
                        full = self._normalize_url(full)
                        if self._is_valid(full):
                            links.add(full)
            meta = soup.find('meta', attrs={'http-equiv': 'refresh'})
            if meta and meta.get('content'):
                content = meta['content']
                url_match = re.search(r'url=([^\s]+)', content, re.I)
                if url_match:
                    refresh_url = url_match.group(1)
                    full = urljoin(base_url, refresh_url)
                    full = self._normalize_url(full)
                    if self._is_valid(full):
                        links.add(full)
        except:
            pass
        return links

    def _extract_from_js(self, url, html):
        links = set()
        try:
            raw_urls = re.findall(r'["\'](https?://[^\s"\']+)["\']', html)
            for raw in raw_urls:
                full = self._normalize_url(raw)
                if self._is_valid(full):
                    links.add(full)
            relative = re.findall(r'["\'](/(?:[^\s"\']+\.(?:php|asp|aspx|jsp|html|htm|js|json|xml|css))["\']', html)
            for rel in relative:
                full = urljoin(url, rel)
                full = self._normalize_url(full)
                if self._is_valid(full):
                    links.add(full)
            api_patterns = re.findall(r'["\'](/api/[^\s"\']+)["\']', html)
            for api in api_patterns:
                full = urljoin(url, api)
                full = self._normalize_url(full)
                if self._is_valid(full):
                    links.add(full)
        except:
            pass
        return links

    def _fetch_page(self, url):
        try:
            session = get_session()
            if self.headers:
                session.headers.update(self.headers)
            if self.cookies:
                session.cookies.update(self.cookies)
            time.sleep(self.delay)
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code == 200:
                return resp.text
            return None
        except:
            return None

    def _fetch_js_page(self, url):
        if not self.use_js or not self.driver:
            return None
        try:
            self.driver.get(url)
            time.sleep(1)
            html = self.driver.page_source
            return html
        except:
            return None

    def _crawl_page(self, url, depth):
        if depth > self.max_depth:
            return []
        with self.visited_lock:
            if url in self.visited:
                return []
            self.visited.add(url)
        html = self._fetch_page(url)
        if not html and self.use_js:
            html = self._fetch_js_page(url)
        if not html:
            return []
        links = self._extract_from_html(html, url)
        js_links = self._extract_from_js(url, html)
        links.update(js_links)
        new_links = []
        with self.visited_lock:
            for link in links:
                if link not in self.visited and link not in self.all_urls:
                    new_links.append(link)
                    self.all_urls.add(link)
        if depth < self.max_depth:
            for link in new_links:
                self.queue.put((link, depth + 1))
        return new_links

    def crawl(self):
        color_print(f"Starting crawl on {self.start_url} (depth={self.max_depth}, threads={self.threads}, js={self.use_js})", 'header')
        self.queue.put((self.start_url, 0))
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            while True:
                try:
                    url, depth = self.queue.get(timeout=3)
                except queue.Empty:
                    break
                futures.append(executor.submit(self._crawl_page, url, depth))
                if len(futures) > self.threads * 2:
                    for future in as_completed(futures[:self.threads]):
                        future.result()
                    futures = futures[self.threads:]
            for future in as_completed(futures):
                future.result()
        if self.driver:
            self.driver.quit()
        color_print(f"Crawl finished. Found {len(self.all_urls)} unique URLs.", 'success')
        return list(self.all_urls)

def crawl_site(start_url, threads=30, depth=4, same_domain=True, delay=0.05, use_js=False):
    crawler = SmartCrawler(start_url, threads, depth, same_domain, delay, respect_robots=False, use_js=use_js)
    return crawler.crawl()