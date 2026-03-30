from flask import Flask, render_template, request
from tools import vulnerability_scanner, port_scanner, link_crawler, directory_scanner, network_info
import os

app = Flask(__name__)

# -------------------------------
# Home Route
# -------------------------------
@app.route('/')
def home():
    return render_template('index.html')


# -------------------------------
# Vulnerability Scan
# -------------------------------
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    result = vulnerability_scanner(url)
    return render_template('index.html', result=result)


# -------------------------------
# Port Scan
# -------------------------------
@app.route('/portscan', methods=['POST'])
def portscan():
    target = request.form['target']
    ports = port_scanner(target)
    return render_template('index.html', ports=ports)


# -------------------------------
# Link Crawler
# -------------------------------
@app.route('/crawl', methods=['POST'])
def crawl():
    url = request.form['url']
    links = link_crawler(url)
    return render_template('index.html', links=links)


# -------------------------------
# Directory Scanner
# -------------------------------
@app.route('/dirscan', methods=['POST'])
def dirscan():
    url = request.form['url']
    dirs = directory_scanner(url)
    return render_template('index.html', dirs=dirs)


# -------------------------------
# Network Info
# -------------------------------
@app.route('/netinfo')
def netinfo():
    net = network_info()
    return render_template('index.html', net=net)


# -------------------------------
# Run App (IMPORTANT FOR CLOUD)
# -------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Render uses this
    app.run(host="0.0.0.0", port=port)