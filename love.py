import os
import time
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import csv

# Configuration
WAF_HOST = "0.0.0.0"  # Bind to all network interfaces
WAF_PORT = 8080
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 80
LOG_FILE = "logs/malicious.log"
MAX_REQUESTS = 100  # Maximum allowed requests per time window
TIME_WINDOW = 60  # Time window in seconds
REDIRECT_URL = "https://krishnagopaljha.github.io/blockedbylove/"  # Redirect URL for malicious requests

# Initialize request tracker for DDoS mitigation
request_tracker = {}

# Helper functions for reading malicious patterns from CSV files
def load_patterns_from_csv(file_path):
    """Load malicious patterns from a CSV file."""
    patterns = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row:
                    patterns.append(row[0].strip())  # Assuming malicious patterns are in the first column
    return patterns

# Load patterns from CSV files
XSS_PATTERNS = load_patterns_from_csv('database/xss.csv')
SQLI_PATTERNS = load_patterns_from_csv('database/sqli.csv')
XML_PATTERNS = load_patterns_from_csv('database/xml.csv')

# DDoS Detection
def detect_ddos(ip_address):
    """
    Detect potential DDoS attacks based on IP-based request rate limiting.
    :param ip_address: IP address of the client
    :return: Tuple (bool, str) indicating whether a DDoS attempt was detected and a message
    """
    current_time = time.time()
    if ip_address not in request_tracker:
        request_tracker[ip_address] = {"count": 1, "start_time": current_time}
        return False, ""
    
    tracker = request_tracker[ip_address]
    elapsed_time = current_time - tracker["start_time"]

    if elapsed_time < TIME_WINDOW:
        tracker["count"] += 1
        if tracker["count"] > MAX_REQUESTS:
            return True, f"DDoS detected: {ip_address} exceeded {MAX_REQUESTS} requests in {TIME_WINDOW} seconds."
    else:
        tracker["count"] = 1
        tracker["start_time"] = current_time

    return False, ""

def clean_up_tracker():
    """
    Clean up old entries in the tracker to prevent memory bloat.
    """
    current_time = time.time()
    to_delete = [ip for ip, tracker in request_tracker.items() if current_time - tracker["start_time"] > TIME_WINDOW]
    for ip in to_delete:
        del request_tracker[ip]

# Detection functions for XSS, SQLi, and XML injection
def detect_xss(data):
    """
    Check for XSS injection attempts.
    :param data: Data to be checked (query string or body content)
    :return: Tuple (bool, str) indicating if XSS is detected and a message
    """
    for pattern in XSS_PATTERNS:
        if pattern in data:
            return True, f"XSS detected: {pattern}"
    return False, ""

def detect_sqli(data):
    """
    Check for SQL Injection attempts.
    :param data: Data to be checked (query string or body content)
    :return: Tuple (bool, str) indicating if SQLi is detected and a message
    """
    for pattern in SQLI_PATTERNS:
        if pattern in data:
            return True, f"SQLi detected: {pattern}"
    return False, ""

def detect_xml(data):
    """
    Check for XML Injection attempts.
    :param data: Data to be checked (query string or body content)
    :return: Tuple (bool, str) indicating if XML injection is detected and a message
    """
    for pattern in XML_PATTERNS:
        if pattern in data:
            return True, f"XML Injection detected: {pattern}"
    return False, ""

# WAF Request Handler
class WAFHandler(BaseHTTPRequestHandler):
    def log_malicious_activity(self, message):
        """Log detected malicious activity to a file."""
        with open(LOG_FILE, "a") as log_file:
            log_file.write(message + "\n")

    def check_malicious_input(self, ip, data):
        """
        Check for malicious activity including DDoS, XSS, SQLi, and XML injection.
        :param ip: IP address of the client
        :param data: Data (query string or body content) to check for malicious input
        :return: (bool, str): Whether malicious activity was detected and a message
        """
        # DDoS Detection
        ddos_detected, ddos_message = detect_ddos(ip)
        if ddos_detected:
            self.log_malicious_activity(ddos_message)
            return True, ddos_message

        # XSS Detection
        xss_detected, xss_message = detect_xss(data)
        if xss_detected:
            self.log_malicious_activity(xss_message)
            return True, xss_message

        # SQL Injection Detection
        sqli_detected, sqli_message = detect_sqli(data)
        if sqli_detected:
            self.log_malicious_activity(sqli_message)
            return True, sqli_message

        # XML Injection Detection
        xml_detected, xml_message = detect_xml(data)
        if xml_detected:
            self.log_malicious_activity(xml_message)
            return True, xml_message

        return False, ""

    def handle_request(self, method="GET", body=None):
        """Process the request and block if malicious input is detected."""
        # Check query parameters for malicious input
        parsed_url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_url.query)

        for key, values in query.items():
            for value in values:
                malicious, message = self.check_malicious_input(self.client_address[0], value)
                if malicious:
                    # Redirect user and block the request
                    self.send_response(302)
                    self.send_header('Location', REDIRECT_URL)
                    self.end_headers()
                    return

        # Check POST body for malicious input
        if body:
            malicious, message = self.check_malicious_input(self.client_address[0], body)
            if malicious:
                # Redirect user and block the request
                self.send_response(302)
                self.send_header('Location', REDIRECT_URL)
                self.end_headers()
                return

        # Forward the request if clean
        self.forward_request(method, body)

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        self.handle_request(method="POST", body=post_data)

    def forward_request(self, method="GET", body=None):
        """Forward the request to the upstream server and send back the response."""
        conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT)
        if method == "GET":
            conn.request("GET", self.path, headers=self.headers)
        elif method == "POST":
            conn.request("POST", self.path, body, headers=self.headers)

        response = conn.getresponse()
        self.send_response(response.status)
        for key, value in response.getheaders():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(response.read())
        conn.close()

def start_monitoring_server():
    """Start the monitoring server in a separate thread, bound to all network interfaces."""
    os.system("python3 monitoring/app.py")

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)

    # Start the monitoring server in a separate thread
    threading.Thread(target=start_monitoring_server, daemon=True).start()

    # Start the WAF server
    server = HTTPServer((WAF_HOST, WAF_PORT), WAFHandler)
    print(f"WAF running on {WAF_HOST}:{WAF_PORT}")
    server.serve_forever()
