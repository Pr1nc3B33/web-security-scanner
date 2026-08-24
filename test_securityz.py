from cybertruckz.report import format_report
from cybertruckz.checks import (
    check_security_headers,
    check_information_disclosure,
    check_exposed_paths,
    check_cookie_flags,
    check_directory_listing,
    check_mixed_content,
)

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

    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)            

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
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
        
    findings = check_security_headers("https://anything.com")
    assert len(findings) == 0     

def test_directory_listing_detected(monkeypatch):
    def fake_get(url, timeout=5):
         return FakeResponse(status_code=200, text="<title>Directory listing for /uploads/</title>")
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_directory_listing("https://anything.com")
    assert len(findings) >= 1

def test_directory_no_listing(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(status_code=200, text="<html>normal page</html>")
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_directory_listing("https://anything.com")
    assert len(findings) == 0

def test_mixed_content_detected(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(text='<img src="http://example.com/logo.png">')
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_mixed_content("https://anything.com")
    assert len(findings) >= 1

def test_mixed_content_clean(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(text='<img src="https://example.com/logo.png">')
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_mixed_content("https://anything.com")
    assert len(findings) == 0

def test_mixed_content_skips_http_site(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(test='<img src="http://insecure.com/x.png">')
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_mixed_content("http://anything.com")
    assert len(findings) == 0 

def test_information_disclosure_detected(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(headers={"Server": "Apache/2.4.29"})
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_information_disclosure("https://anything.com") 
    assert len(findings) >= 1

def test_information_dislosure_clean(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(headers={"Server": "cloudfare"})
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_information_disclosure("https://anything.com")
    assert len(findings) == 0    

def test_exposed_paths_detected(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(status_code=200)
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_exposed_paths("https://anything.com")
    assert len(findings) >= 1

def  test_exposed_paths_clean(monkeypatch):
    def fake_get(url, timeout=5):
        return FakeResponse(status_code=404)
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_exposed_paths("https://anything.com")
    assert len(findings) == 0   

class FakeCookie:
    def __init__(self, name, secure=False, http_only=False, samesite=False):
        self.name = name
        self.secure = secure
        self._http_only = http_only
        self._rest = {"SameSite": "Lax"} if samesite else {}

    def has_nonstandard_attr(self, attr):
        return attr == "HttpOnly" and self._http_only 

class FakeResponse:
    def __init__(self, headers=None, status_code=200, text="", cookies=None):
        self.headers = headers if headers is not None else {}
        self.status_code = status_code
        self.text = text
        self.cookies = cookies if cookies is not None else {}

def test_cookie_flags_all_missing(monkeypatch):
    insecure_cookie = FakeCookie(name="Session")
    def fake_get(url, timeout=5):
        return FakeResponse(cookies=[insecure_cookie])
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_cookie_flags("https://anything.com")
    assert len(findings) == 3

def test_cookie_flags_all_present(monkeypatch):
    secure_cookie = FakeCookie(name="session", secure=True, http_only=True, samesite=True)
    def fake_get(url, timeout=5):
        return FakeResponse(cookies=[secure_cookie])
    monkeypatch.setattr("cybertruckz.checks.requests.get", fake_get)
    findings = check_cookie_flags("https://anything.com")
    assert len(findings) == 0            





        


