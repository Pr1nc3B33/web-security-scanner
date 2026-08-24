from cybertruckz.checks import (
    check_security_headers,
    check_tls_certificate,
    check_information_disclosure,
    check_exposed_paths,
    check_cookie_flags,
    check_directory_listing,
    check_mixed_content,
)

def run_all_checks(url):
    findings = []
    findings.extend(check_security_headers(url))
    findings.extend(check_tls_certificate(url))
    findings.extend(check_information_disclosure(url))
    findings.extend(check_exposed_paths(url))
    findings.extend(check_cookie_flags(url))
    findings.extend(check_directory_listing(url))
    findings.extend(check_mixed_content(url))
    return findings

