# Tests for the 12 feature extractors (FEATURE_CONTRACT.md).

from ml.datasets.prepare import extract_features


def test_simple_https_url():
    f = extract_features("https://example.com/")
    assert f["url_length"] == 20
    assert f["hostname_length"] == 11
    assert f["path_length"] == 1
    assert f["query_length"] == 0
    assert f["subdomain_count"] == 0
    assert f["has_ip_hostname"] is False
    assert f["has_punycode"] is False
    assert f["has_embedded_credentials"] is False
    assert f["has_unusual_port"] is False
    assert f["suspicious_keyword_count"] == 0


def test_www_subdomain_counts_as_one():
    f = extract_features("https://www.example.com/")
    assert f["subdomain_count"] == 1


def test_ip_hostname_detected():
    f = extract_features("http://192.168.1.1/")
    assert f["has_ip_hostname"] is True


def test_punycode_detected():
    f = extract_features("https://xn--e1afmkfd.xn--p1ai/")
    assert f["has_punycode"] is True


def test_suspicious_keywords_counted():
    f = extract_features("https://example.com/login/verify-account?secure=1")
    assert f["suspicious_keyword_count"] >= 3  # login, verify, account, secure


def test_unusual_port_detected():
    f = extract_features("https://example.com:8443/")
    assert f["has_unusual_port"] is True


def test_default_ports_not_unusual():
    assert extract_features("https://example.com:443/")["has_unusual_port"] is False
    assert extract_features("http://example.com:80/")["has_unusual_port"] is False


def test_query_length():
    f = extract_features("https://example.com/?a=1&b=2")
    assert f["query_length"] == 7  # "a=1&b=2"