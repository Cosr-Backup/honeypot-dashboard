"""Fixtures for honeypot dashboard tests."""
import json
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))


XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '" onmouseover="alert(1)',
    "javascript:alert('xss')",
    '<svg/onload=alert(1)>',
    "';!--\"<XSS>=&{()}",
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert(1)>',
]


def _make_log_line(eventid, **kwargs):
    """Build a Cowrie JSON log line."""
    base = {
        "eventid": eventid,
        "timestamp": "2026-03-01T12:00:00.000000Z",
        "src_ip": "1.2.3.4",
        "session": "abc123",
    }
    base.update(kwargs)
    return json.dumps(base)


@pytest.fixture
def sample_log_lines():
    """Valid Cowrie log lines for testing."""
    return [
        _make_log_line("cowrie.session.connect", src_ip="1.2.3.4"),
        _make_log_line("cowrie.login.failed", src_ip="1.2.3.4", username="root", password="admin"),
        _make_log_line("cowrie.login.failed", src_ip="1.2.3.4", username="root", password="123456"),
        _make_log_line("cowrie.login.success", src_ip="1.2.3.4", username="root", password="toor"),
        _make_log_line("cowrie.command.input", src_ip="1.2.3.4", input="uname -a"),
        _make_log_line("cowrie.command.input", src_ip="1.2.3.4", input="cat /etc/passwd"),
        _make_log_line("cowrie.session.connect", src_ip="5.6.7.8",
                       timestamp="2026-03-01T13:00:00.000000Z", session="def456"),
        _make_log_line("cowrie.login.failed", src_ip="5.6.7.8", username="admin", password="password",
                       timestamp="2026-03-01T13:00:01.000000Z", session="def456"),
    ]


@pytest.fixture
def xss_log_lines():
    """Log lines with XSS payloads in attacker-controlled fields."""
    lines = []
    for payload in XSS_PAYLOADS:
        lines.append(_make_log_line("cowrie.login.failed", src_ip="10.0.0.1",
                                     username=payload, password=payload))
        lines.append(_make_log_line("cowrie.command.input", src_ip="10.0.0.1",
                                     input=payload))
    return lines


@pytest.fixture
def mock_geo_cache():
    """Pre-populated GeoIP cache (no network calls needed)."""
    return {
        "1.2.3.4": {
            "country": "Netherlands", "countryCode": "NL", "region": "North Holland",
            "city": "Amsterdam", "lat": 52.37, "lon": 4.89,
            "isp": "DigitalOcean", "org": "DigitalOcean",
        },
        "5.6.7.8": {
            "country": "China", "countryCode": "CN", "region": "Beijing",
            "city": "Beijing", "lat": 39.9, "lon": 116.4,
            "isp": "Alibaba", "org": "Alibaba Cloud",
        },
        "10.0.0.1": {
            "country": "Unknown", "countryCode": "", "region": "",
            "city": "", "lat": 0, "lon": 0,
            "isp": "Unknown", "org": "",
        },
    }
