import os
import time
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import http.client
import csv

# Configuration
WAF_HOST = "0.0.0.0"  # Bind to all network interfaces
WAF_PORT = 8080       # WAF listening port
UPSTREAM_HOST = "127.0.0.1"  # Upstream server address
UPSTREAM_PORT = 80    # Upstream server port
LOG_FILE = "logs/malicious.log"
TIME_WINDOW = 60  # Time window in seconds for DDoS detection
MAX_REQUESTS = 100  # Max allowed requests per time window

# Tracking client requests for DDoS detection
request_tracker = {}

# Load malicious patterns from CSV
def load_patterns(file_path):
    """Load malicious patterns from a CSV file."""
    patterns = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            reader = csv.reader(f)
            patterns = [row[0].strip() for row in reader if row]
    return patterns

# Load patterns for different attacks
XSS_PATTERNS = load_patterns("database/xss.csv")
SQLI_PATTERNS = load_patterns("database/sqli.csv")
XML_PATTERNS = load_patterns("database/xml.csv")

# DDoS Detection
def detect_ddos(ip_address):
    """Detect potential DDoS attacks."""
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

# Pattern Detection
def detect_patterns(data, patterns):
    """Check data against a list of malicious patterns."""
    for pattern in patterns:
        if pattern in data:
            return True, f"Detected: {pattern}"
    return False, ""

# WAF Request Handler
class WAFHandler(BaseHTTPRequestHandler):
    def log_activity(self, message):
        """Log detected activity to a file."""
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.ctime()}: {message}\n")

    def handle_request(self, method, body=None):
        """Process incoming request and detect malicious activity."""
        ip_address = self.client_address[0]

        # DDoS Detection
        ddos_detected, ddos_message = detect_ddos(ip_address)
        if ddos_detected:
            self.log_activity(ddos_message)
            self.block_request(ddos_message)
            return

        # Inspect query string
        parsed_url = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        for key, values in query_params.items():
            for value in values:
                for attack_type, patterns in [("XSS", XSS_PATTERNS), ("SQLi", SQLI_PATTERNS), ("XML", XML_PATTERNS)]:
                    detected, message = detect_patterns(value, patterns)
                    if detected:
                        self.log_activity(f"{attack_type} {message}")
                        self.block_request(message)
                        return

        # Inspect POST body
        if method == "POST" and body:
            for attack_type, patterns in [("XSS", XSS_PATTERNS), ("SQLi", SQLI_PATTERNS), ("XML", XML_PATTERNS)]:
                detected, message = detect_patterns(body, patterns)
                if detected:
                    self.log_activity(f"{attack_type} {message}")
                    self.block_request(message)
                    return

        # Forward clean requests
        self.forward_request(method, body)

    def block_request(self, reason):
        """Block and serve a custom HTML file for malicious requests."""
        try:
            with open("block.html", "r") as f:
                html_content = f.read()
            self.send_response(403)  # 403 Forbidden status
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html_content.encode("utf-8"))
            print(f"Blocked request: {reason}")
        except FileNotFoundError:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Error: block.html file not found.")
            print(f"Error serving block.html: {reason}")

    def forward_request(self, method, body=None):
        """Forward clean requests to the upstream server."""
        try:
            conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=10)
            if method == "GET":
                conn.request("GET", self.path, headers=self.headers)
            elif method == "POST":
                conn.request("POST", self.path, body=body, headers=self.headers)
            response = conn.getresponse()
            self.send_response(response.status)
            for header, value in response.getheaders():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.read())
            conn.close()
        except Exception as e:
            self.send_error(500, f"Error forwarding request: {e}")

    def do_GET(self):
        """Handle GET requests."""
        self.handle_request("GET")

    def do_POST(self):
        """Handle POST requests."""
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        self.handle_request("POST", body=post_data)

# Start the Monitoring Script
def start_monitoring_app():
    """Start the monitoring script in a separate thread."""
    os.system("python3 monitoring/app.py")

# Run the WAF
if __name__ == "__main__":
    # Ensure required directories exist
    os.makedirs("logs", exist_ok=True)
    os.makedirs("database", exist_ok=True)

    # Start monitoring script in a separate thread
    threading.Thread(target=start_monitoring_app, daemon=True).start()

    # Start the WAF server with multithreading
    print(f"WAF starting on {WAF_HOST}:{WAF_PORT}")
    server = ThreadingHTTPServer((WAF_HOST, WAF_PORT), WAFHandler)
    server.serve_forever()
