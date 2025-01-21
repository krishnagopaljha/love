# LiteWAF 

LiteWAF is a simple Web Application Firewall (WAF) designed to detect and block malicious activities such as DDoS, XSS, SQL Injection, and XML Injection attacks. It works by inspecting incoming HTTP requests and checking for malicious patterns in the request data, such as query parameters, POST bodies, and headers.

## Features

- **DDoS Protection**: Limits the number of requests from a single IP in a specified time window.
- **XSS Protection**: Detects and blocks potential Cross-Site Scripting (XSS) attacks.
- **SQL Injection Protection**: Identifies and blocks SQL Injection (SQLi) attempts.
- **XML Injection Protection**: Protects against XML-based injection attacks.
- **Malicious Activity Logging**: Logs detected malicious activities for further analysis.

## Requirements

- Python 3.x
- Required Python packages (which can be installed using `pip`):
    - `http.client`
    - `http.server`
    - `urllib.parse`
    - `csv`
    - `threading`
    - `time`
    - `os`

## Installation

1. Clone the repository or download the files:
    ```bash
    git clone https://github.com/krishnagopaljha/love.git
    cd love
    ```

2. Install the required dependencies (Till today every package added is a part of python standard library so there is no need to manully install anything`):
    ```bash
    pip install -r requirements.txt
    ```

3. Make sure the necessary folders and files are present (e.g., `logs`, `database/xss.csv`, `database/sqli.csv`, and `database/xml.csv`).

## Configuration

- **WAF_HOST**: The IP address where the WAF server will listen. Default is `0.0.0.0` (binds to all network interfaces).
- **WAF_PORT**: The port on which the WAF server listens. Default is `8080`.
- **UPSTREAM_HOST**: The IP address of the upstream server. Default is `127.0.0.1`.
- **UPSTREAM_PORT**: The port of the upstream server. Default is `80`.
- **LOG_FILE**: Path to the log file where malicious activities are recorded. Default is `logs/malicious.log`.
- **MAX_REQUESTS**: The maximum number of requests an IP can make in the specified time window (in seconds). Default is `100`.
- **TIME_WINDOW**: Time window for DDoS detection in seconds. Default is `60` seconds.
- **REDIRECT_URL**: URL where the user will be redirected if malicious activity is detected.

## Running the WAF

To run the WAF server:

```bash
python love.py
