
# WEB SECURITY SCANNER

A command-line tool that scans a website for common security misconfigurations and produces a clear, severity-ranked report — in the terminal or as a branded PDF. Written in Python.

## WHAT IT CHECKS

- **Security headers** — flags missing HTTP security headers (HSTS, Content-Security-Policy, X-Frame-Options, and others).
- **TLS / certificate** — checks whether the site's certificate is valid, expired, or expiring soon.
- **Information disclosure** — detects when the server leaks software versions via `Server` or `X-Powered-By` headers.
- **Exposed sensitive paths** — probes for accidentally public files such as `.env`, `.git/config`, and config backups.
- **Cookie flags** — checks cookies for the `Secure`, `HttpOnly`, and `SameSite` security flags.
- **Directory listing** — detects browsable directories that expose their file contents.
- **Mixed content** — flags HTTPS pages that load resources over insecure HTTP.

## PROJECT STRUCTURE

cybertruckz/
checks.py # the seven security checks
scanner.py # orchestration — runs all checks
report.py # text and PDF report generation
securityz.py # command-line entry point
test_securityz.py # test suite

## INSTALLATION 


```bash
git clone https://github.com/Pr1nc3B33/web-security-scanner.git
cd web-security-scanner
pip install requests reportlab
```

## Usage

Scan a site and print the report to the terminal:

```bash
python3 securityz.py https://example.com
```

Also generate a branded PDF report:

```bash
python3 securityz.py https://example.com --pdf
```

See `sample_report.pdf` in this repo for an example of the PDF output.

## Testing

Run the test suite with:

```bash
pytest test_securityz.py -v
```

The suite uses mocking to test the network-facing checks without making live requests.

## Responsible use

This tool performs active checks against the target site, including requesting specific paths. **Only scan websites you own or have explicit written permission to test.** Scanning systems without authorization may violate the Computer Fraud and Abuse Act (CFAA) or equivalent laws in your jurisdiction.

## Built with

Python · requests · reportlab · pytest






