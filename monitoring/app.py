from flask import Flask, render_template
import os

app = Flask(__name__)

# Path to the log file
LOG_FILE = "logs/malicious.log"

# Function to read and categorize logs by attack type
def read_logs():
    logs = {
        "sqli": [],
        "xss": [],
        "ddos": [],
        "xml": []
    }
    
    # Read the log file and categorize based on attack type
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as log_file:
            for line in log_file:
                if "SQLi" in line:
                    logs["sqli"].append(line)
                elif "XSS" in line:
                    logs["xss"].append(line)
                elif "DDoS" in line:
                    logs["ddos"].append(line)
                elif "XML" in line:
                    logs["xml"].append(line)
    
    return logs

@app.route("/")
def home():
    # Get categorized logs
    logs = read_logs()
    return render_template("index.html", logs=logs)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
