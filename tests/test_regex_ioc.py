"""
Tests for IoC regex patterns from ReportSummarizer.

Tests cover:
  - IPv4 extraction (including private IP filtering)
  - Domain extraction (including IGNORE_DOMAINS and IGNORE_EXTENSIONS)
  - Hash extraction (MD5, SHA1, SHA256)
  - CVE extraction
  - Email extraction
"""

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from summarizer.report_summarizer import (
    REGEX_PATTERNS,
    IGNORE_DOMAINS,
    IGNORE_EXTENSIONS,
)


# ── IPv4 ─────────────────────────────────────────────────


class TestIPv4Regex:
    pattern = re.compile(REGEX_PATTERNS["ipv4"])

    def test_public_ip(self):
        assert self.pattern.search("contact 203.0.113.45 for info")

    def test_another_public_ip(self):
        assert self.pattern.search("C2: 198.51.100.23")

    def test_excludes_localhost(self):
        assert self.pattern.search("127.0.0.1") is None

    def test_excludes_private_10(self):
        assert self.pattern.search("10.0.0.1") is None

    def test_excludes_private_192(self):
        assert self.pattern.search("192.168.1.1") is None

    def test_excludes_private_172(self):
        assert self.pattern.search("172.16.0.1") is None

    def test_valid_172_public(self):
        # 172.32.x.x is public (only 172.16-31 is private)
        assert self.pattern.search("172.32.0.1")

    def test_edge_255(self):
        assert self.pattern.search("255.255.255.255")

    def test_no_match_invalid(self):
        assert self.pattern.search("999.999.999.999") is None

    def test_multiple_ips(self):
        text = "IPs: 203.0.113.1 and 198.51.100.2"
        matches = self.pattern.findall(text)
        assert len(matches) == 2


# ── Domain ───────────────────────────────────────────────


class TestDomainRegex:
    pattern = re.compile(REGEX_PATTERNS["domain"])

    def test_simple_domain(self):
        assert self.pattern.search("malware-c2.com")

    def test_subdomain(self):
        assert self.pattern.search("evil.update.example.org")

    def test_domain_with_tld(self):
        match = self.pattern.search("visit evil-update.com today")
        assert match is not None
        assert "evil-update.com" in match.group(0)


class TestDomainFiltering:

    def test_ignore_extensions_filter(self):
        domain = "script.js"
        ext = "." + domain.rsplit(".", 1)[-1]
        assert ext in IGNORE_EXTENSIONS

    def test_ignore_known_domains(self):
        assert "google.com" in IGNORE_DOMAINS
        assert "microsoft.com" in IGNORE_DOMAINS
        assert "github.com" in IGNORE_DOMAINS

    def test_malicious_domain_not_filtered(self):
        assert "evil-update.com" not in IGNORE_DOMAINS


# ── Hashes ───────────────────────────────────────────────


class TestHashRegex:

    def test_md5(self):
        pat = re.compile(REGEX_PATTERNS["md5"])
        assert pat.search("hash: d41d8cd98f00b204e9800998ecf8427e")

    def test_md5_length(self):
        pat = re.compile(REGEX_PATTERNS["md5"])
        m = pat.search("d41d8cd98f00b204e9800998ecf8427e")
        assert m is not None
        assert len(m.group(0)) == 32

    def test_sha1(self):
        pat = re.compile(REGEX_PATTERNS["sha1"])
        assert pat.search("da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_sha256(self):
        pat = re.compile(REGEX_PATTERNS["sha256"])
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert pat.search(h)

    def test_sha256_length(self):
        pat = re.compile(REGEX_PATTERNS["sha256"])
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        m = pat.search(h)
        assert len(m.group(0)) == 64

    def test_not_hex_no_match(self):
        pat = re.compile(REGEX_PATTERNS["md5"])
        assert pat.search("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") is None


# ── CVE ──────────────────────────────────────────────────


class TestCVERegex:
    pattern = re.compile(REGEX_PATTERNS["cve"])

    def test_standard_cve(self):
        assert self.pattern.search("exploiting CVE-2024-38063")

    def test_cve_five_digit(self):
        assert self.pattern.search("CVE-2023-12345")

    def test_cve_four_digit(self):
        assert self.pattern.search("CVE-2021-4034")

    def test_multiple_cves(self):
        text = "CVE-2024-38063 and CVE-2023-12345 were exploited"
        matches = self.pattern.findall(text)
        assert len(matches) == 2

    def test_no_match_partial(self):
        assert self.pattern.search("CVE-2024") is None


# ── Email ────────────────────────────────────────────────


class TestEmailRegex:
    pattern = re.compile(REGEX_PATTERNS["email"])

    def test_simple_email(self):
        assert self.pattern.search("contact attacker@evil.com")

    def test_complex_email(self):
        assert self.pattern.search("user.name+tag@subdomain.example.org")

    def test_no_match_without_at(self):
        assert self.pattern.search("not-an-email.com") is None


# ── Integration: full report extraction ──────────────────


class TestFullReportExtraction:
    """Test IoC extraction from a realistic report fragment."""

    def test_extract_all_ioc_types(self, sample_report):
        results = {}
        for name, pattern in REGEX_PATTERNS.items():
            results[name] = re.findall(pattern, sample_report)

        # IPs (should find 203.0.113.45 and 198.51.100.23, not private)
        assert len(results["ipv4"]) >= 2
        assert "203.0.113.45" in " ".join(results["ipv4"])

        # CVE
        assert any("CVE-2024-38063" in c for c in results["cve"])

        # Hashes
        assert len(results["md5"]) >= 1
        assert len(results["sha256"]) >= 1
