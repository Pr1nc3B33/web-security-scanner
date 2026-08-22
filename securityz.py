import argparse
import requests
import ssl
import socket
from datetime import datetime, timezone 
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer 

def check_security_headers(url):
    expected_headers = {
        "Strict-Transport-Security": { "severity": "High", "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to force HTTPS."}, 
        "Content-Security-Policy": { "severity": "High", "recommendation": "Define a Content-Security-Policy to restrict which sources scripts and resources can load from"}, 
        "X-Frame-Options": { "severity": "Medium", "recommendation": "Add 'X-Frame-Options: DENY' to prevent clickjacking.",},  
        "X-Content-Type-Options": { "severity": "Medium", "recommendation": "Add 'X-Content-Type-Options:nosniff' to stop MIME-type sniffing."},
        "Referrer-Policy": { "severity": "Low", "recommendation": "Add 'Referrer-Policy:no-referrer-when-downgrade'(or stricter) to limit referrer leakage."},
        "Permissions-Policy": {"severity": "Low", "recommendation": "Set a Permissions-Policy to restrict access to browser features like camera and geolocation."},
    }    

    findings = []

    try:

        resp = requests.get(url, timeout=5)
        headers = resp.headers

        for header_name, info in expected_headers.items():
            if header_name not in headers:
                finding = {
                    "severity": info["severity"], "title": f"Missing {header_name} header", 
                    "detail": f"The {header_name} header is not set in the response.", "recommendation": info["recommendation"],
                }
                findings.append(finding)

    except requests.RequestException as e:
        findings.append({
            "severity": "High",
            "title": "Connection Failed",
            "detail": f"Failed to connect to URL: {str(e)}",
            "recommendation": "Verify the URL is correct and the site is reachable.",
        })

    return findings    

def check_tls_certificate(url):
    findings = []

    hostname = url.replace("https://","").replace("http://","").split("/")[0]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        expires_str = cert["notAfter"] 
        expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z")
        expires = expires.replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days

        if days_left < 0:
            findings.append({
                "severity": "High",
                "title": "Certificate has expired", 
                "detail": f"The certificate expired {abs(days_left)} days ago.",
                "recommendation": "Renew immediately."
            })
            
        elif days_left < 14:
            findings.append({
                "severity": "High",
                "title": "Certificate expiring soon",
                "detail": f"The certificate expires in {days_left} days.",
                "recommendation": "Renew now."
            })

        elif days_left < 30:
            findings.append({
                "severity": "Medium",
                "title": "Certificate expiring within 30 days",
                "detail": f"The certificate expires in {days_left} days.",
                "recommendation": "Review for renewal soon."
            })        


    except ssl.SSLError as e:
        findings.append({
            "severity": "High",
            "title": "TLS/SSL error",
            "detail": f"Could not establish a secure connection: {str(e)}",
            "recommendation": "Investigate the certificate; it may be invalid, self-signed, or misconfigured.",
        })

    except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
        findings.append({
            "severity": "High",
            "title": "Connection failed",
            "detail": f"Could not connect to {hostname} on port 443: {str(e)}",
            "recommendation": "Verify the site is reachable over HTTPS.",
        })

    return findings               

def check_information_disclosure(url):
    findings = []
    disclosure_headers = {
        "Server": {
            "severity": "Low",
            "recommendation": "Configure the server to suppress or obscure its version in the Server header (e.g. 'ServerTokens Prod' on Apache).",
        },

        "X-Powered-By": {
            "severity": "Low", 
            "recommendation": "Remove the X-Powered-By header (e.g.'expose_php = Off' in PHP, or app.disable('x-powered-by') in Express).",
        },
    }

    try: 
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        for header_name, info in disclosure_headers.items():
            if header_name in headers and any(char.isdigit() for char in headers[header_name]):
                finding = {
                    "severity": info["severity"],
                    "title": f"Information disclosure via {header_name} header",
                    "detail": f"The {header_name} header reveals: {headers[header_name]}",
                    "recommendation": info["recommendation"],
                }
                findings.append(finding)

    except requests.RequestException as e:
        findings.append({
            "severity": "High",
            "title": "Connection failed",
            "detail": f"Failed to connect to URL: {str(e)}",
            "recommendation": "Verify the URL is correct and the site is reachable.",
        })
    return findings

def check_exposed_paths(url):
    findings = []
    sensitive_paths = [
        "/.env",
        "/.git/config",
        "/wp-config.php.bak",
        "/backup.zip",
        "/.htaccess",
    ]    

    base = url.rstrip("/")

    for path in sensitive_paths:
        try:
            resp = requests.get(base + path, timeout=5)
            if resp.status_code == 200:
                findings.append({
                    "severity": "High",
                    "title": f"Sensitive file exposed: {path}",
                    "detail": f"Exposed sensitive file: {path}",
                    "recommendation": "Block access to the file and, critically, rotate any secrets it may have exposed.",
                })




        except requests.RequestException:
        
            continue 
    return findings                    

def check_cookie_flags(url):    
    findings = []
    try:
        resp = requests.get(url, timeout=5)
        for cookie in resp.cookies:
            if not cookie.secure:
                findings.append({
                    "severity": "Medium",
                    "title": f"Secure flag missing on cookie {cookie.name}",
                    "detail":f"{cookie.name} is missing a secure flag.",
                    "recommendation": "Set the Secure flag on this cookie so it is only transmitted over HTTPS.",
                })
            if not cookie.has_nonstandard_attr("HttpOnly"):
                findings.append({
                    "severity": "Medium",
                    "title": f"HttpOnly missing on cookie {cookie.name}",
                    "detail": f"{cookie.name} is missing HttpOnly attribute.",
                    "recommendation": "Set the HttpOnly flag so the cookie cannot be accessed by client-side JavaScript, mitigating theft via XSS."
                })
            if "SameSite" not in cookie._rest:
                findings.append({
                    "severity": "Low",
                    "title": f"SameSite missing on cookie {cookie.name}",
                    "detail": f"{cookie.name} is missing SameSite.",
                    "recommendation": "Set the SameSite attribute (Lax or Strict) to protect against cross-site request forgery (CSRF)."
                })        



    except requests.RequestException as e:
        findings.append({
            "severity": "High",
            "title": "Connection failed",
            "detail": f"Failed to connect to URL: {str(e)}",
            "recommendation": "Verify the URL is correct and the site is reachable.",

        })
    return findings    

def run_all_checks(url):
    findings = []
    findings.extend(check_security_headers(url))
    findings.extend(check_tls_certificate(url))
    findings.extend(check_information_disclosure(url))
    findings.extend(check_exposed_paths(url))
    findings.extend(check_cookie_flags(url))
    findings.extend(check_directory_listing(url))
    return findings

def format_report(url, findings):
    lines = []
    lines.append(f"Security scan report for: {url}")
    lines.append(f"Total findings: {len(findings)}")
    lines.append("=" * 50)

    for severity in ["High", "Medium", "Low"]:
        matched = [f for f in findings if f["severity"] == severity]

        if matched:
            lines.append(f"\n{severity.upper()} ({len(matched)})")
            lines.append("-" * 20)

            for item in matched:
                lines.append(f"Title: {item.get('title', 'N/A')}")
                lines.append(f"Detail: {item.get('detail')}")
                lines.append(f"Recommendation: {item.get('recommendation')}")
                lines.append("")



    return "\n".join(lines) 

def generate_pdf_report(url, findings, filename="security_report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=letter) 
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#0A1F3D"),
    )
    heading_style = ParagraphStyle(
        "SeverityHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#00C8E6"),
    )

    story = []
    story.append(Paragraph("Security Scan Report", title_style))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",styles["Normal"]))
    story.append(Paragraph(f"Target: {url}", styles["Normal"]))
    story.append(Paragraph(f"Total findings: {len(findings)}", styles["Normal"]))
    story.append(Spacer(1, 20))

    for severity in ["High", "Medium", "Low"]:
        matched = [f for f in findings if f["severity"] == severity]

        if matched:
            story.append(Paragraph(f"{severity.upper()} ({len(matched)})", heading_style))
            story.append(Spacer(1, 6))

            for item in matched:
                title = item.get("title", "N/A")
                detail = item.get("detail", "No details provided.")
                rec = item.get("recommendation", "No recommendation provided.")
                
                story.append(Paragraph(f"<b>Title:</b> {title}", styles["Normal"]))
                story.append(Paragraph(f"<b>Detail:</b> {detail}", styles["Normal"]))
                story.append(Paragraph(f"<b>Recommendation:</b> {rec}", styles["Normal"]))

                story.append(Spacer(1, 12))
                



    doc.build(story)
    return filename 

def check_directory_listing(url):
    findings = []
    directories = [
        "/images/",
        "/uploads/",
        "/files/",
        "/backup/",
        "/admin/",
    ]  

    base = url.rstrip("/")       

    for directory in directories:
        try:
            resp = requests.get(base + directory, timeout=5)
            body = resp.text

            if resp.status_code == 200 and ("Index of /" in body or "Directory listing for" in body):
                findings.append({
                    "severity": "Medium",
                    "title": f"Directory listing enabled: {directory}",
                    "detail": f"The directory {directory} returns a browsable file index, exposing its contents.",
                    "recommendation": "Disable directory listing (e.g. 'Options -Indexes' on Apache, or 'autoindex off' on nginx).",

                })

        except requests.RequestException:
            continue

    return findings

def check_mixed_content(url):
     findings = [] 

     if not url.startswith("https://"):
         return findings

     try:
         resp = requests.get(url, timeout=5)
         body = resp.text

         if 'src="http://' in body or 'href="http://' in body:
            findings.append({
                "severity": "Medium",
                "title": "Mixed content detected",
                "detail": f"Https loading insecure resources",
                "recommendation": "Update those references to https or protocol-relative URLs",
            })

     except requests.RequestException as e:
         findings.append({
             "severity": "High",
             "title": "Connection Failed",
             "detail": f"Failed to connect to URL: {str(e)}",
             "recommendation": "Verify the URL is correct and the site is reachable"
         })
     return findings    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan a website for common security misconfigurations."
        )    

    parser.add_argument("url", help="The URL to scan, e.g. https://example.com")
    parser.add_argument("--pdf", action="store_true", help="Also generate a branded PDF report.",)

    args = parser.parse_args()

    findings = run_all_checks(args.url)
    print(format_report(args.url, findings))

    if args.pdf:
        filename = generate_pdf_report(args.url, findings)
        print(f"\nPDF report saved to: {filename}")










   




