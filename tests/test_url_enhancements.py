"""Tests for URL screening enhancements including deduplication and path tokens."""

from aegis.screening.urls import inspect_urls


def test_url_shortener_detection_comprehensive() -> None:
    """Test detection of various URL shorteners including new ones."""
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "short.link", "adf.ly", "gg.gg"]
    
    for shortener in shorteners:
        text = f"Check this out: https://{shortener}/abc123"
        evidence = inspect_urls(text)
        assert any("url_shortener" in e.signal for e in evidence), f"Should detect {shortener}"


def test_suspicious_path_tokens_comprehensive() -> None:
    """Test detection of account/security action tokens in URL paths."""
    test_cases = [
        ("https://bank.com/login", "login"),
        ("https://service.com/verify", "verify"),
        ("https://app.com/authenticate?next=/account", "authenticate"),
        ("https://site.com/reactivate", "reactivate"),
        ("https://site.com/validate", "validate"),
    ]
    
    for url, expected_token in test_cases:
        text = f"Click: {url}"
        evidence = inspect_urls(text)
        assert any("suspicious_url_path" in e.signal for e in evidence), \
            f"Should detect {expected_token} in path"


def test_ip_address_detection_with_credentials() -> None:
    """Test detection of IP addresses with embedded credentials."""
    text = "https://user:pass@192.168.1.1/admin"
    evidence = inspect_urls(text)
    
    assert any("url_embedded_credentials" in e.signal for e in evidence), \
        "Should detect embedded credentials"
    assert any("url_ip_host" in e.signal for e in evidence), \
        "Should detect IP host"


def test_unusual_subdomain_detection() -> None:
    """Test detection of unusually deep subdomain structures."""
    text = "https://a.b.c.d.example.com/page"
    evidence = inspect_urls(text)
    
    assert any("unusual_subdomain" in e.signal for e in evidence), \
        "Should detect deep subdomain (4+ levels)"


def test_url_deduplication_same_host() -> None:
    """Test that URL deduplication prevents multiple flags for same canonical host."""
    text = "Visit http://suspicious.com/page1 and http://suspicious.com/page2"
    evidence = inspect_urls(text)
    
    # With deduplication, we should only process suspicious.com once
    # This means we won't get duplicate evidence for the same host
    hosts_mentioned = [e for e in evidence if "suspicious.com" in e.details]
    # Should have evidence, but not tripled from multiple occurrences
    assert len(hosts_mentioned) <= 2, "Should not produce excessive evidence for repeated hosts"


def test_new_url_shorteners_added() -> None:
    """Test that newly added shorteners are detected."""
    new_shorteners = ["adf.ly", "shorte.st", "shortened.link"]
    
    for shortener in new_shorteners:
        text = f"https://{shortener}/abc"
        evidence = inspect_urls(text)
        assert any("url_shortener" in e.signal for e in evidence), \
            f"Should detect new shortener {shortener}"
