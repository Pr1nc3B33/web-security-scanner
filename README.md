
# WEB SECURITY SCANNER 

A command-line tool that scans a website for common security misconfiguartions and produces a clear severity-ranked report. Written in Python.

## WHAT IT CHECKS

- **Security Headers** - flags missing HTTP security headers (HSTS, Content-Security-Policy, X-Frame_Options, and others), 
                         that protect agaisnt common web attacks.

- **TLS / Certificate** - checks whether the site's certificate is valid, expired or expiring soon. 

- **Information Disclosure** - detects when the server leaks its software versions via `Server` or `X-Powered-By` headers. 

- **Exposed Sensitive Paths** - probes for accidently public files such as `.env`, `.git/config`, and config backups.

- **Cookie Flags** - checks cookies for the `Secure`, `HttpOnly`, and `SameSite` security flags. 

## INSTALLATION 

```bash
git clone https://github.com/Pr1nc3B33/web-security-scanner.git
cd web-security-scanner
pip install requests
```


## USAGE

```bash
python3 securityz.py https://example.com
```

Example output:


Security scan report for: https://example.com
Total findings: 2
MEDIUM (1)

Title: HttpOnly missing on cookie session_id
Detail: The cookie 'session_id' is not marked HttpOnly.
Recommendation: Set the HttpOnly flag so the cookie cannot be accessed by client-side JavaScript.

LOW (1)

Title: Missing Permissions-Policy header
...

## Responsible use

This tool performs active checks against the target site, including requesting specific paths. **Only scan websites you own or have explicit written permission to test.** Scanning systems without authorization may violate the Computer Fraud and Abuse Act (CFAA) or equivalent laws in your jurisdiction.

## Built with

Python · requests · standard library (ssl, socket, argparse)






