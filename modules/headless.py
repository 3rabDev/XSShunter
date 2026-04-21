#!/usr/bin/env python3

import logging

logger = logging.getLogger(__name__)

try:
    from selenium import webdriver
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False


def verify_xss(url: str, payload: str, timeout: int = 5) -> bool:
    if not SELENIUM_AVAILABLE:
        return False
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1280,900")
    driver = None
    try:
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        try:
            WebDriverWait(driver, timeout).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert.accept()
            return True
        except TimeoutException:
            return payload in driver.page_source
    except WebDriverException:
        logger.debug("Headless verification failed for %s", url, exc_info=True)
        return False
    except Exception:
        logger.debug("Unexpected headless verification failure for %s", url, exc_info=True)
        return False
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                logger.debug("Failed to close WebDriver", exc_info=True)
