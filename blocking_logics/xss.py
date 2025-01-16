import requests
import re
import csv
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
            patterns = [row["pattern"] for row in reader]
    except FileNotFoundError:
        print(f"Pattern file not found: {file_path}. Ensure the file exists.")
    return patterns

# Load patterns at the module level
XSS_PATTERNS = load_patterns()

def is_valid_url(url):
    """Validate the URL format."""
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def detect_xss(data):
    """
    Detect XSS attempts in the provided data.
    :param data: Input data to check for XSS
    :return: Tuple (bool, str) indicating detection status and message
    """
    if not data:
        return False, ""
    
    for pattern in XSS_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return True, f"XSS detected with pattern: {pattern}"
    return False, ""

def is_vulnerable(url):
    """Test if a URL is vulnerable to XSS based on loaded patterns."""
    try:
        response = requests.get(url)
        detected, message = detect_xss(response.text)
        if detected:
            print(f"[VULNERABLE] {message}")
            return True
    except requests.RequestException as e:
        print(f"[ERROR] Failed to send request: {e}")
    return False

def main():
    url = input("Enter the URL to test: ").strip()

    if not is_valid_url(url):
        print("[ERROR] Invalid URL format. Please provide a valid URL.")
        return

    print(f"Testing URL: {url}")
    if is_vulnerable(url):
        print("[RESULT] The URL is vulnerable to XSS based on pattern detection.")
    else:
        print("[RESULT] The URL does not appear vulnerable to XSS.")

if __name__ == "__main__":
    main()
