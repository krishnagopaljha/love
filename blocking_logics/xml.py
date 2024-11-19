import re
import csv

def load_patterns(file_path="databse/xml.csv"):
    """
    Load malicious patterns for XML Injection detection from a CSV file.
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

# Load patterns at the module level so they're ready when `detect_xml_injection` is called
XML_PATTERNS = load_patterns()

def detect_xml_injection(data):
    """
    Detect XML injection attempts in the provided data.
    :param data: Input data to check for XML injection
    :return: Tuple (bool, str) indicating detection status and message
    """
    if not data:
        return False, ""
    
    for pattern in XML_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return True, f"XML Injection detected with pattern: {pattern}"
    return False, ""
