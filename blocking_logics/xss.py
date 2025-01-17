import csv
import re
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from urllib.parse import urlparse

def load_patterns(file_path="database/xss.csv"):
    """
    Load malicious patterns for XSS detection from a CSV file.
    :param file_path: Path to the CSV file containing patterns
    :return: List of malicious patterns
    """
    patterns = []
    try:
        with open(file_path, mode="r") as file:
            reader = csv.DictReader(file)
            patterns = [row["pattern"] for row in reader if "pattern" in row]
    except FileNotFoundError:
        print(f"[ERROR] Pattern file not found: {file_path}. Ensure the file exists.")
    except Exception as e:
        print(f"[ERROR] An error occurred while loading patterns: {e}")
    return patterns

def is_valid_url(url):
    """Validate the URL format."""
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def detect_xss(data, patterns):
    """
    Detect XSS attempts in the provided data.
    :param data: Input data to check for XSS
    :param patterns: List of malicious patterns to check against
    :return: Tuple (bool, str) indicating detection status and message
    """
    if not data:
        return False, ""
    
    for pattern in patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True, f"XSS detected with pattern: {pattern}"
    return False, ""

def fetch_rendered_source(url):
    """
    Fetch the fully rendered HTML content of a webpage using Selenium.
    :param url: The URL to fetch
    :return: Rendered HTML content as a string
    """
    try:
        # Configure Selenium WebDriver
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")  # Run in headless mode
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")

        # Path to your ChromeDriver executable (adjust as needed)
        service = Service("/path/to/chromedriver")
        driver = webdriver.Chrome(service=service, options=options)

        driver.get(url)
        rendered_html = driver.page_source
        driver.quit()
        return rendered_html
    except Exception as e:
        print(f"[ERROR] Failed to fetch rendered content: {e}")
        return ""

def is_vulnerable(url, patterns):
    """
    Test if a URL is vulnerable to XSS based on loaded patterns.
    :param url: The URL to test
    :param patterns: List of malicious patterns to check against
    :return: True if the URL is vulnerable, False otherwise
    """
    try:
        # Fetch both static and rendered content
        response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
        response_text = response.text

        rendered_text = fetch_rendered_source(url)

        # Check both sources for XSS patterns
        for text in [response_text, rendered_text]:
            detected, message = detect_xss(text, patterns)
            if detected:
                print(f"[VULNERABLE] {message}")
                return True
    except requests.RequestException as e:
        print(f"[ERROR] Failed to send request: {e}")
    return False

def block_xss(url):
    """
    Block a URL if XSS is detected.
    :param url: The URL to test
    """
    print(f"[BLOCKED] The URL '{url}' is blocked due to potential XSS vulnerability.")

def main():
    patterns = load_patterns()
    if not patterns:
        print("[ERROR] No patterns loaded. Exiting.")
        return

    url = input("Enter the URL to test: ").strip()

    if not is_valid_url(url):
        print("[ERROR] Invalid URL format. Please provide a valid URL.")
        return

    print(f"Testing URL: {url}")
    if is_vulnerable(url, patterns):
        block_xss(url)
    else:
        print("[RESULT] The URL does not appear vulnerable to XSS.")

if __name__ == "__main__":
    main()
