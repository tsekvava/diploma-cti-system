"""
Shared pytest fixtures for CTI Pipeline tests.

Fixtures provide:
  - Access to the real MITRE SQLite database (mitre.db)
  - Sample text fragments for regex testing
  - Mock LLM responses for pipeline tests without Ollama
"""

import sys
from pathlib import Path

import pytest

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(scope="session")
def project_root():
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def mitre_db_path(project_root):
    """Path to the real mitre.db — skip if not built yet."""
    db = project_root / "knowledge_base" / "mitre.db"
    if not db.exists():
        pytest.skip("mitre.db not found — run: python3 -m knowledge_base.mitre_catalog --stix")
    return db


@pytest.fixture(scope="session")
def normalizer(mitre_db_path):
    from knowledge_base.normalizer import EntityNormalizer
    return EntityNormalizer(db_path=mitre_db_path)


@pytest.fixture(scope="session")
def enricher(mitre_db_path):
    from knowledge_base.query_enricher import QueryEnricher
    return QueryEnricher(db_path=str(mitre_db_path))


# --------------- sample texts ---------------

SAMPLE_REPORT_TEXT = """
On February 12, 2026, researchers at Securelist published a report detailing
a campaign attributed to APT28 (also known as Fancy Bear, STRONTIUM, and Sofacy).

The attackers used spearphishing emails with malicious DOCX attachments
exploiting CVE-2024-38063 to gain initial access.  Once inside the network
they deployed Cobalt Strike beacons communicating with 203.0.113.45 and
evil-update[.]com over port 443.  Additional C2 infrastructure included
198.51.100.23.  Mimikatz was used for credential harvesting.

File hashes observed:
  MD5:    d41d8cd98f00b204e9800998ecf8427e
  SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""


@pytest.fixture
def sample_report():
    return SAMPLE_REPORT_TEXT
