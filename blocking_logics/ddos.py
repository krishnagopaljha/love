import time

# Configuration for rate limiting
MAX_REQUESTS = 100  # Maximum allowed requests per time window
TIME_WINDOW = 60  # Time window in seconds

# Dictionary to track request counts and timestamps per IP
request_tracker = {}

def detect_ddos(ip_address):
    """
    Detect potential DDoS attacks based on IP-based request rate limiting.
    :param ip_address: IP address of the client
    :return: Tuple (bool, str) indicating whether a DDoS attempt was detected and a message
    """
    current_time = time.time()
    if ip_address not in request_tracker:
        # Initialize tracking for this IP
        request_tracker[ip_address] = {"count": 1, "start_time": current_time}
        return False, ""
    
    # Get the tracked data for the IP
    tracker = request_tracker[ip_address]
    elapsed_time = current_time - tracker["start_time"]

    if elapsed_time < TIME_WINDOW:
        # Within the time window, increment the request count
        tracker["count"] += 1
        if tracker["count"] > MAX_REQUESTS:
            return True, f"DDoS detected: {ip_address} exceeded {MAX_REQUESTS} requests in {TIME_WINDOW} seconds."
    else:
        # Reset the tracker if the time window has expired
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
