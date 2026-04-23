#!/usr/bin/env python3

import logging
import shutil
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from selenium import webdriver
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support import expected_conditions as EC
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
    EC = None
    ChromeDriverManager = None


def _find_chrome_executable() -> Optional[str]:
    """Find Chrome/Chromium executable on the system."""
    import sys
    import os
    
    # Common Chrome executable names
    chrome_names = [
        "google-chrome",
        "google-chrome-stable",
        "google-chrome-beta",
        "chrome",
        "chromium",
        "chromium-browser",
    ]
    
    # Platform-specific paths
    if sys.platform == "win32":
        # Windows paths
        possible_paths = [
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles%\Chromium\Application\chrome.exe"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
    elif sys.platform == "darwin":
        # macOS paths
        possible_paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
    
    # Try to find in PATH
    for name in chrome_names:
        chrome_path = shutil.which(name)
        if chrome_path:
            return chrome_path
    
    return None


def check_chrome_setup() -> Tuple[bool, str]:
    if not SELENIUM_AVAILABLE:
        return False, (
            "Selenium not installed.\n"
            "Install it with: pip install selenium\n"
            "Also install webdriver-manager: pip install webdriver-manager"
        )
    
    chrome_path = _find_chrome_executable()
    if not chrome_path:
        import sys
        if sys.platform == "win32":
            install_guide = (
                "Download from: https://www.google.com/chrome/\n"
                "Or: https://www.chromium.org/getting-involved/download-chromium/"
            )
        elif sys.platform == "darwin":
            install_guide = (
                "Install with: brew install --cask google-chrome\n"
                "Or download from: https://www.google.com/chrome/"
            )
        else:
            install_guide = (
                "Install with: sudo apt-get install google-chrome-stable\n"
                "Or: sudo yum install google-chrome-stable\n"
                "Or: sudo pacman -S chromium"
            )
        return False, f"Chrome not found.\n{install_guide}"
    try:
        import sys

        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "from modules.headless import _build_driver; d=_build_driver(); d.quit(); print('ok')",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if probe.returncode != 0:
            message = (probe.stderr or probe.stdout or "WebDriver probe failed").strip()
            return False, f"Chrome found at: {chrome_path}\nWebDriver startup failed: {message}"
        return True, f"Chrome and WebDriver are working: {chrome_path}"
    except Exception as exc:
        return False, f"Chrome found at: {chrome_path}\nWebDriver startup failed: {exc}"


def _build_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1440,1024")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    try:
        return webdriver.Chrome(options=options)
    except Exception:
        if ChromeDriverManager is None:
            raise
        service = Service(ChromeDriverManager().install())
        return webdriver.Chrome(service=service, options=options)


def verify_xss(url: str, payload: str, timeout: int = 8) -> bool:
    if not SELENIUM_AVAILABLE:
        return False
    driver = None
    try:
        driver = _build_driver()
        driver.get(url)
        try:
            WebDriverWait(driver, timeout).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert.accept()
            return True
        except TimeoutException:
            pass
        page_source = driver.page_source or ""
        if payload and payload in page_source:
            return True
        try:
            logs = driver.get_log("browser")
        except Exception:
            logs = []
        payload_markers = ["alert", "confirm", "prompt", payload[:30] if payload else ""]
        for entry in logs:
            message = str(entry.get("message", "")).lower()
            if any(marker and marker.lower() in message for marker in payload_markers):
                return True
        return False
    except WebDriverException:
        logger.debug("Headless verification failed for %s", url, exc_info=True)
        return False
    except Exception:
        logger.debug("Unexpected headless verification error for %s", url, exc_info=True)
        return False
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                logger.debug("WebDriver cleanup failed", exc_info=True)
