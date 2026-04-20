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

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import time
import os
import logging

logger = logging.getLogger(__name__)

def verify_xss(url: str, payload: str, timeout: int = 5) -> bool:
    """Verify XSS payload using headless browser."""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    
    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        
        driver.get(url)
        
        alert_detected = False
        try:
            WebDriverWait(driver, timeout).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            alert_detected = True
        except TimeoutException:
            pass
        
        if alert_detected:
            return True
        
        page_source = driver.page_source
        if payload in page_source:
            return True
        
        return False
        
    except WebDriverException as e:
        logger.debug(f"WebDriver error: {e}")
        return False
    except Exception as e:
        logger.debug(f"Verification error: {e}")
        return False
    finally:
        if driver:
            try:
                driver.quit()
            except Exception as e:
                logger.debug(f"Driver quit error: {e}")