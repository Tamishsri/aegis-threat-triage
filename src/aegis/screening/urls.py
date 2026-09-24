"""Offline-only URL structure inspection; it never contacts a URL."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from aegis.evidence.models import Evidence, EvidenceSource, EvidenceStrength

URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
TRAILING_URL_PUNCTUATION = ".,!?;:)]}>\"'"

SHORTENER_HOSTS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "rb.gy", "cutt.ly"}
)
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
}
SUSPICIOUS_PATH_TOKENS = re.compile(
    r"(?i)\b(?:login|verify|secure|account|update|password|otp|payment|confirm)\b"
)


@dataclass(frozen=True, slots=True)
class ExtractedUrl:
    value: str
    span: tuple[int, int]


def extract_urls(text: str) -> tuple[ExtractedUrl, ...]:
    """Extract apparent web URLs without following or resolving them."""

    urls: list[ExtractedUrl] = []
    for match in URL_PATTERN.finditer(text):
        value = match.group(0).rstrip(TRAILING_URL_PUNCTUATION)
        if not value:
            continue
        urls.append(ExtractedUrl(value=value, span=(match.start(), match.start() + len(value))))
    return tuple(urls)


def inspect_urls(text: str, *, source: EvidenceSource = EvidenceSource.TEXT) -> tuple[Evidence, ...]:
    """Convert suspicious URL structure into qualitative evidence.

    HTTPS absence is deliberately not a signal. These checks are structural
    hints, not reputation lookups or proof that a domain is malicious.
    """

    evidence: list[Evidence] = []
    for extracted in extract_urls(text):
        raw_url = extracted.value
        normalized_url = raw_url if "://" in raw_url else f"https://{raw_url}"
        parsed = urlsplit(normalized_url)
        host = (parsed.hostname or "").casefold().rstrip(".")
        if not host:
            continue

        details_prefix = f"URL structure observed: {raw_url}"
        if parsed.username is not None:
            evidence.append(
                _url_evidence(
                    "url_embedded_credentials",
                    EvidenceStrength.STRONG,
                    f"{details_prefix}; it contains an embedded username before the host.",
                    extracted.span,
                    source,
                )
            )

        if _is_ip_address(host):
            evidence.append(
                _url_evidence(
                    "url_ip_host",
                    EvidenceStrength.MODERATE,
                    f"{details_prefix}; it uses an IP address as the host.",
                    extracted.span,
                    source,
                )
            )
        else:
            if "xn--" in host:
                evidence.append(
                    _url_evidence(
                        "url_punycode",
                        EvidenceStrength.MODERATE,
                        f"{details_prefix}; the host contains an IDN/punycode label.",
                        extracted.span,
                        source,
                    )
                )
            if host in SHORTENER_HOSTS or any(host.endswith(f".{name}") for name in SHORTENER_HOSTS):
                evidence.append(
                    _url_evidence(
                        "url_shortener",
                        EvidenceStrength.MODERATE,
                        f"{details_prefix}; it uses a URL-shortening host.",
                        extracted.span,
                        source,
                    )
                )
            if _has_brand_domain_mismatch(host):
                evidence.append(
                    _url_evidence(
                        "brand_domain_mismatch",
                        EvidenceStrength.MODERATE,
                        f"{details_prefix}; a brand token appears on a non-official host.",
                        extracted.span,
                        source,
                    )
                )
            if len(host.split(".")) >= 4:
                evidence.append(
                    _url_evidence(
                        "unusual_subdomain",
                        EvidenceStrength.WEAK,
                        f"{details_prefix}; it has an unusually deep subdomain structure.",
                        extracted.span,
                        source,
                    )
                )

        if SUSPICIOUS_PATH_TOKENS.search(f"{parsed.path}?{parsed.query}"):
            evidence.append(
                _url_evidence(
                    "suspicious_url_path",
                    EvidenceStrength.WEAK,
                    f"{details_prefix}; its path or query contains an account/security action term.",
                extracted.span,
                source,
                )
            )
    return tuple(evidence)


def _url_evidence(
    signal: str,
    strength: EvidenceStrength,
    details: str,
    span: tuple[int, int],
    source: EvidenceSource,
) -> Evidence:
    return Evidence(
        source=source,
        signal=signal,
        strength=strength,
        extractor="deterministic_url_inspection",
        details=details,
        span=span,
    )


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _has_brand_domain_mismatch(host: str) -> bool:
    labels = host.split(".")
    for brand, official_domain in KNOWN_BRANDS.items():
        if brand not in labels and not any(brand in label for label in labels):
            continue
        if host == official_domain or host.endswith(f".{official_domain}"):
            continue
        return True
    return False
