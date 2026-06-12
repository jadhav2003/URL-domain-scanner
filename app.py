from flask import Flask, render_template, request, make_response
import whois
import socket
import dns.resolver
import ssl
import datetime
import requests
import sqlite3
import os
from database import init_db
from dateutil import parser as dateparser
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import io

app = Flask(__name__)
init_db()

VIRUSTOTAL_API_KEY = "308cf0d82cd07587f4bbc9e376d51c98f6f5cd9c4eb609a1dd9a1d9633fca1c2"

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "IP Not Found"

def get_dns_records(domain):
    try:
        records = dns.resolver.resolve(domain, 'A')
        return [record.to_text() for record in records]
    except:
        return ["No DNS Records Found"]

def get_ssl_info(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        if cert:
            return "SSL Certificate Found"
        else:
            return "No SSL Certificate"
    except:
        return "No SSL Certificate"

def get_geo_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data['status'] == 'success':
            return {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", "Unknown"),
                "timezone": data.get("timezone", "Unknown"),
                "lat": data.get("lat", ""),
                "lon": data.get("lon", ""),
            }
        else:
            return None
    except:
        return None

def check_blacklist(domain, ip):
    results = []
    is_blacklisted = False

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=5
        )
        data = response.json()
        if data.get("query_status") == "is_host":
            is_blacklisted = True
            results.append("Found in URLHaus malware database")
        else:
            results.append("Not found in URLHaus")
    except:
        results.append("URLHaus check failed")

    try:
        payload = {"query": "search_ioc", "search_term": domain}
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            timeout=5
        )
        data = response.json()
        if data.get("query_status") == "ok" and data.get("data"):
            is_blacklisted = True
            results.append("Found in ThreatFox IOC database")
        else:
            results.append("Not found in ThreatFox")
    except:
        results.append("ThreatFox check failed")

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=proxy,hosting,query",
            timeout=5
        )
        data = response.json()
        if data.get("proxy"):
            is_blacklisted = True
            results.append("IP is a known proxy/VPN")
        elif data.get("hosting"):
            results.append("IP belongs to a hosting provider")
        else:
            results.append("IP is not a known proxy")
    except:
        results.append("IP reputation check failed")

    return results, is_blacklisted

def check_virustotal(url):
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            harmless    = stats.get("harmless", 0)
            undetected  = stats.get("undetected", 0)
            total       = malicious + suspicious + harmless + undetected
            engines_flagged = []
            results = data["data"]["attributes"]["last_analysis_results"]
            for engine, result in results.items():
                if result["category"] in ["malicious", "suspicious"]:
                    engines_flagged.append(f"{engine}: {result['result']}")
            return {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total,
                "engines_flagged": engines_flagged[:10],
                "error": None
            }
        elif response.status_code == 404:
            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            return {
                "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total": 0,
                "engines_flagged": [],
                "error": "URL submitted for first scan. Try again in 1 minute."
            }
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
    except Exception as e:
        return {"error": f"VirusTotal check failed: {str(e)}"}

def check_phishing_indicators(url, domain_info, ssl_status):
    flags = []
    risk_score = 0
    domain_age_str = "Unknown"

    if len(url) > 75:
        flags.append("URL is unusually long")
        risk_score += 20

    suspicious_keywords = ['login', 'verify', 'secure', 'update', 'account',
                           'bank', 'confirm', 'password', 'signin', 'ebayisapi',
                           'webscr', 'free', 'lucky', 'prize']
    for word in suspicious_keywords:
        if word in url.lower():
            flags.append(f"Suspicious keyword found: '{word}'")
            risk_score += 25

    try:
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, str):
            creation_date = dateparser.parse(creation_date)
        age_days = (datetime.datetime.now() - creation_date).days
        years = age_days // 365
        months = (age_days % 365) // 30
        domain_age_str = f"{years} years, {months} months (created {creation_date.strftime('%d %b %Y')})"
        if age_days < 180:
            flags.append(f"Domain is very new ({age_days} days old)")
            risk_score += 30
    except:
        flags.append("Could not determine domain age")
        risk_score += 10
        domain_age_str = "Could not determine"

    if "No SSL" in ssl_status:
        risk_score += 20
        flags.append("No SSL certificate detected")

    reputation_score = max(0, 100 - risk_score)

    if risk_score == 0:
        risk_level = "Safe"
    elif risk_score < 40:
        risk_level = "Suspicious"
    else:
        risk_level = "Dangerous"

    return flags, risk_level, risk_score, reputation_score, domain_age_str

def save_scan(url, registrar, ip_address, ssl_info, risk_level, risk_score, geo_info):
    conn = sqlite3.connect('scans.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (url, registrar, ip_address, ssl_status, risk_level, risk_score, country, city, isp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        url, registrar, ip_address, ssl_info, risk_level, risk_score,
        geo_info['country'] if geo_info else "Unknown",
        geo_info['city'] if geo_info else "Unknown",
        geo_info['isp'] if geo_info else "Unknown"
    ))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = sqlite3.connect('scans.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans ORDER BY scanned_at DESC')
    scans = cursor.fetchall()
    conn.close()
    return scans

def generate_pdf(scan_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=40, leftMargin=40,
                            topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    story = []

    # Title style
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=6
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.HexColor('#16213e'),
        spaceBefore=14,
        spaceAfter=6
    )
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=4
    )

    # Title
    story.append(Paragraph("URL & Domain Intelligence Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.datetime.now().strftime('%d %B %Y, %H:%M:%S')}",
        normal_style
    ))
    story.append(Spacer(1, 0.2*inch))

    # Risk banner table
    risk = scan_data['risk_level']
    if risk == "Safe":
        risk_color = colors.HexColor('#238636')
    elif risk == "Suspicious":
        risk_color = colors.HexColor('#d29922')
    else:
        risk_color = colors.HexColor('#da3633')

    risk_table = Table(
        [[f"Risk Level: {risk}",
          f"Risk Score: {scan_data['risk_score']}",
          f"Reputation: {scan_data['reputation_score']}/100"]],
        colWidths=[160, 160, 160]
    )
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), risk_color),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 11),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWHEIGHT', (0,0), (-1,-1), 30),
        ('ROUNDEDCORNERS', [6,6,6,6]),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 0.2*inch))

    # Domain Info
    story.append(Paragraph("Domain Information", heading_style))
    domain_data = [
        ["Field", "Value"],
        ["URL", scan_data['url']],
        ["Registrar", scan_data['registrar']],
        ["IP Address", scan_data['ip_address']],
        ["Domain Age", scan_data['domain_age']],
        ["SSL Status", scan_data['ssl_info']],
    ]
    domain_table = Table(domain_data, colWidths=[150, 350])
    domain_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#16213e')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#f8f9fa'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(domain_table)

    # Geolocation
    if scan_data.get('geo_info'):
        story.append(Paragraph("Geolocation & ISP", heading_style))
        geo = scan_data['geo_info']
        geo_data = [
            ["Field", "Value"],
            ["Country", geo.get('country','')],
            ["Region", geo.get('region','')],
            ["City", geo.get('city','')],
            ["ISP", geo.get('isp','')],
            ["Organisation", geo.get('org','')],
            ["Timezone", geo.get('timezone','')],
            ["Coordinates", f"{geo.get('lat','')}, {geo.get('lon','')}"],
        ]
        geo_table = Table(geo_data, colWidths=[150, 350])
        geo_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('ROWBACKGROUNDS', (0,1), (-1,-1),
             [colors.HexColor('#f8f9fa'), colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(geo_table)

    # Threat Indicators
    story.append(Paragraph("Threat Indicators", heading_style))
    if scan_data['flags']:
        for flag in scan_data['flags']:
            story.append(Paragraph(f"• {flag}", normal_style))
    else:
        story.append(Paragraph("• No suspicious indicators detected", normal_style))

    # Blacklist
    story.append(Paragraph("Blacklist Check", heading_style))
    for result in scan_data.get('blacklist_results', []):
        story.append(Paragraph(f"• {result}", normal_style))

    # VirusTotal
    vt = scan_data.get('vt_result')
    if vt and not vt.get('error'):
        story.append(Paragraph("VirusTotal Analysis", heading_style))
        vt_data = [
            ["Harmless", "Malicious", "Suspicious", "Undetected", "Total"],
            [str(vt['harmless']), str(vt['malicious']),
             str(vt['suspicious']), str(vt['undetected']), str(vt['total'])]
        ]
        vt_table = Table(vt_data, colWidths=[95, 95, 95, 95, 100])
        vt_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 11),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('PADDING', (0,0), (-1,-1), 10),
            ('BACKGROUND', (1,1), (1,1), colors.HexColor('#fff0f0')),
        ]))
        story.append(vt_table)

        if vt['engines_flagged']:
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("Engines that flagged this URL:", normal_style))
            for engine in vt['engines_flagged']:
                story.append(Paragraph(f"• {engine}", normal_style))

    # DNS Records
    story.append(Paragraph("DNS Records", heading_style))
    for record in scan_data.get('dns_records', []):
        story.append(Paragraph(f"• {record}", normal_style))

    doc.build(story)
    buffer.seek(0)
    return buffer

# Store last scan in memory for PDF download
last_scan = {}

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan():
    global last_scan
    url = request.form['url']

    try:
        domain_info = whois.whois(url)
        registrar = domain_info.registrar
    except:
        registrar = "Not Found"
        domain_info = None

    ip_address = get_ip(url)
    dns_records = get_dns_records(url)
    ssl_info = get_ssl_info(url)
    geo_info = get_geo_info(ip_address)
    flags, risk_level, risk_score, reputation_score, domain_age = check_phishing_indicators(url, domain_info, ssl_info)
    blacklist_results, is_blacklisted = check_blacklist(url, ip_address)
    vt_result = check_virustotal(url)

    if vt_result and not vt_result.get("error"):
        if vt_result["malicious"] > 0:
            risk_level = "Dangerous"
            risk_score = min(100, risk_score + vt_result["malicious"] * 5)
            reputation_score = max(0, reputation_score - vt_result["malicious"] * 5)

    if is_blacklisted:
        risk_level = "Dangerous"
        risk_score = min(100, risk_score + 50)
        reputation_score = max(0, reputation_score - 50)

    # Save scan data for PDF
    last_scan = {
        'url': url,
        'registrar': registrar,
        'ip_address': ip_address,
        'dns_records': dns_records,
        'ssl_info': ssl_info,
        'flags': flags,
        'risk_level': risk_level,
        'risk_score': risk_score,
        'reputation_score': reputation_score,
        'domain_age': domain_age,
        'geo_info': geo_info,
        'blacklist_results': blacklist_results,
        'is_blacklisted': is_blacklisted,
        'vt_result': vt_result
    }

    save_scan(url, registrar, ip_address, ssl_info, risk_level, risk_score, geo_info)

    return render_template(
        "result.html",
        url=url,
        registrar=registrar,
        ip_address=ip_address,
        dns_records=dns_records,
        ssl_info=ssl_info,
        flags=flags,
        risk_level=risk_level,
        risk_score=risk_score,
        reputation_score=reputation_score,
        domain_age=domain_age,
        geo_info=geo_info,
        blacklist_results=blacklist_results,
        is_blacklisted=is_blacklisted,
        vt_result=vt_result
    )

@app.route('/download-report/<path:url>')
def download_report(url):
    global last_scan
    if not last_scan:
        return "No scan data found. Please scan a URL first.", 404

    pdf_buffer = generate_pdf(last_scan)
    response = make_response(pdf_buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{url}.pdf'
    return response

@app.route('/history')
def history():
    scans = get_all_scans()
    return render_template("history.html", scans=scans)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)