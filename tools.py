import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import socket
from concurrent.futures import ThreadPoolExecutor

headers = {"User-Agent": "Mozilla/5.0"}

# -------------------------------
# Vulnerability Scanner
# -------------------------------
def vulnerability_scanner(url):

    result = []

    sql_payload = "' OR '1'='1"
    xss_payload = "<script>alert('XSS')</script>"

    try:
        r = requests.get(url + sql_payload, headers=headers, timeout=5)
        if "error" in r.text.lower():
            result.append("SQL Injection Possible")
    except:
        result.append("SQL Test Failed")

    try:
        r = requests.get(url + xss_payload, headers=headers, timeout=5)
        if xss_payload in r.text:
            result.append("XSS Vulnerable")
    except:
        result.append("XSS Test Failed")

    if not result:
        result.append("No vulnerabilities detected")

    return result


# -------------------------------
# Port Scanner
# -------------------------------
def port_scanner(target):

    open_ports = []
    ports = [21, 22, 80, 443, 8080]

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        if s.connect_ex((target, port)) == 0:
            open_ports.append(f"{port} OPEN")

        s.close()

    if not open_ports:
        return ["No open ports found"]

    return open_ports


# -------------------------------
# Link Crawler (FAST)
# -------------------------------
def link_crawler(url):

    links = set()

    try:
        r = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                full_link = urljoin(url, href)
                links.add(full_link)

        # Limit results for speed
        links = list(links)[:20]

    except Exception as e:
        return [f"Error: {str(e)}"]

    if not links:
        return ["No links found"]

    return links


# -------------------------------
# Directory Scanner (FAST + THREADING)
# -------------------------------
def directory_scanner(url):

    directories = ["admin", "login", "dashboard", "backup", "uploads"]
    found = []

    def scan_dir(d):
        target = urljoin(url, d)
        try:
            r = requests.get(target, headers=headers, timeout=3)
            if r.status_code == 200:
                return target
        except:
            return None

    # Multithreading for speed
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(scan_dir, directories)

    for res in results:
        if res:
            found.append(res)

    if not found:
        return ["No directories found"]

    return found


# -------------------------------
# Network Info
# -------------------------------
def network_info():

    host = socket.gethostname()
    ip = socket.gethostbyname(host)

    return {"hostname": host, "ip": ip}