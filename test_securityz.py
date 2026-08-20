from securityz import format_report, check_security_headers


def test_format_report_groups_by_severity():
    fake_findings = [
        {"severity": "High", "title": "Test high finding",
        "detail": "d", "recommendation": "r"},
        {"severity": "Low", "title": "Test low finding",
         "detail": "d", "recommendation": "r"},
    ]

    report = format_report("https://test.com", fake_findings)

    assert "HIGH (1)" in report
    assert "LOW (1)" in report
    assert "Test high finding" in report
    assert "Total findings: 2" in report

def test_format_reports_with_empty_lists(): 
    fake_findings = []
    report = format_report("https://test.com", fake_findings)
    assert "Total findings: 0" in report 
    assert "HIGH (0)" not in report   

class FakeResponse:
    def __init__(self, headers):
        self.headers = headers

def test_security_headers_flags_missing(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(headers={})

    monkeypatch.setattr("securityz.requests.get", fake_get)            

    findings = check_security_headers("https://anything.com")

    assert len(findings) == 6
    titles = [f["title"] for f in findings]
    assert "Missing Strict-Transport-Security header" in titles

def test_security_headers_passes_when_present(monkeypatch):
    full_headers = {
        "Strict-Transport-Security": "x",
        "Content-Security-Policy": "x", 
        "X-Frame-Options": "x",
        "X-Content-Type-Options": "x",
        "Referrer-Policy": "x",
        "Permissions-Policy": "x",
    }
    def fake_get(url, timeout=5):
        return FakeResponse(headers=full_headers)
    monkeypatch.setattr("securityz.requests.get", fake_get)
        
    findings = check_security_headers("https://anything.com")
    assert len(findings) == 0     

        


