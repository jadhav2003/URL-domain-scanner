# URL & Domain Intelligence Scanner

A full-stack cybersecurity tool built with Python and Flask that analyzes URLs and domains for threats, phishing indicators, and security intelligence.

## 🔗 Live Demo
https://url-domain-scanner.onrender.com

## 🛡️ Features
- WHOIS Lookup — registrar, domain age, creation date
- DNS Records — A record resolution
- SSL Certificate — HTTPS verification
- Phishing Detection — suspicious keywords, URL length, domain age analysis
- Reputation Score — 0-100 trust score
- Blacklist Check — URLHaus and ThreatFox databases
- VirusTotal Integration — scan against 90+ antivirus engines
- Geolocation & ISP — country, city, coordinates, Google Maps link
- Scan History — SQLite database storing all past scans
- PDF Report — downloadable scan report

## 🧰 Tech Stack
- Backend: Python, Flask
- Database: SQLite
- APIs: VirusTotal, ip-api, URLHaus, ThreatFox
- Frontend: HTML, CSS
- Deployment: Render

## 🚀 Run Locally
```bash
git clone https://github.com/jadhav2003/URL-domain-scanner.git
cd URL-domain-scanner
pip install -r requirements.txt
python app.py
```
## 👤 Author
Riddhi Jadhav
