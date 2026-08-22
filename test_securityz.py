from securityz import format_report, check_security_headers, check_directory_listing, check_mixed_content
import securityz


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
    def __init__(self, headers=None, status_code=200, text=""):
        self.headers = headers if headers is not None else {}
        self.status_code = status_code
        self.text = text

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

def test_directory_listing_detected(monkeypatch):
    def fake_get(url, timeout=5):
         return FakeResponse(status_code=200, text="<title>Directory listing for /uploads/</title>")
    monkeypatch.setattr("securityz.requests.get", fake_get)
    findings = check_directory_listing("https://anything.com")
    assert len(findings) >= 1

def test_directory_no_listing(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(status_code=200, text="<html>normal page</html>")
    monkeypatch.setattr("securityz.requests.get", fake_get)
    findings = check_directory_listing("https://anything.com")
    assert len(findings) == 0

def test_mixed_content_detected(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(text='<img src="http://example.com/logo.png">')
    monkeypatch.setattr("securityz.requests.get", fake_get)
    findings = check_mixed_content("https://anything.com")
    assert len(findings) >= 1

def test_mixed_content_clean(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(text='<img src="https://example.com/logo.png">')
    monkeypatch.setattr("securityz.requests.get", fake_get)
    findings = check_mixed_content("https://anything.com")
    assert len(findings) == 0

def test_mixed_content_skips_http_site(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(test='<img src="http://insecure.com/x.png">')
    monkeypatch.setattr("securityz.requests.get", fake_get)
    findings = check_mixed_content("http://anything.com")
    assert len(findings) == 0    




        


