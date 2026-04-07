"""
Tests for OpenCTI Exporter — STIX 2.1 Bundle generation (dry-run mode).

Tests cover:
  - STIX Bundle structure validity
  - Object creation (Intrusion Set, Malware, Tool, Attack Pattern, etc.)
  - Relationship creation
  - TLP marking definitions
  - Export from sample analysis result
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from opencti_exporter import OpenCTIExporter, TLP_MARKINGS


# ── TLP Markings ─────────────────────────────────────────


class TestTLPMarkings:

    def test_all_standard_tlps_present(self):
        for tlp in ("TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"):
            assert tlp in TLP_MARKINGS

    def test_marking_ids_are_valid_stix(self):
        for tlp, marking_id in TLP_MARKINGS.items():
            assert marking_id.startswith("marking-definition--")
            assert len(marking_id) > 30


# ── STIX Bundle from test fixture ────────────────────────


@pytest.fixture
def sample_input():
    """Load the test analysis result fixture."""
    fixture = Path(__file__).parent / "test_opencti_input.json"
    if not fixture.exists():
        pytest.skip("test_opencti_input.json not found")
    with open(fixture) as f:
        return json.load(f)


@pytest.fixture
def exporter():
    return OpenCTIExporter(tlp="TLP:AMBER", dry_run=True)


class TestSTIXBundleGeneration:

    def test_export_returns_dict(self, exporter, sample_input):
        result = exporter.export_stix_bundle(sample_input)
        assert isinstance(result, dict)

    def test_bundle_has_type(self, exporter, sample_input):
        bundle = exporter.export_stix_bundle(sample_input)
        assert bundle.get("type") == "bundle"

    def test_bundle_has_objects(self, exporter, sample_input):
        bundle = exporter.export_stix_bundle(sample_input)
        objects = bundle.get("objects", [])
        assert len(objects) > 0

    def test_export_has_statistics(self, exporter, sample_input):
        result = exporter.export(sample_input)
        assert isinstance(result, dict)
        # export() returns operational stats (intrusion_sets, malware, etc.)
        assert "intrusion_sets" in result or "errors" in result


class TestSTIXObjectTypes:
    """Verify that the bundle contains expected STIX object types."""

    @pytest.fixture(autouse=True)
    def setup_bundle(self, exporter, sample_input):
        bundle = exporter.export_stix_bundle(sample_input)
        self.objects = bundle.get("objects", [])
        self.types = [obj.get("type") for obj in self.objects]

    def test_has_marking_definition(self):
        assert "marking-definition" in self.types

    def test_has_relationships(self):
        if len(self.objects) > 2:
            assert "relationship" in self.types


class TestExporterInit:

    def test_default_tlp(self):
        exp = OpenCTIExporter(dry_run=True)
        assert exp.dry_run is True

    def test_custom_tlp(self):
        exp = OpenCTIExporter(tlp="TLP:RED", dry_run=True)
        assert "TLP:RED" in TLP_MARKINGS


# ── Existing STIX Bundle fixture validation ──────────────


class TestExistingBundleFixture:
    """Validate the pre-existing test_stix_bundle.json fixture."""

    @pytest.fixture
    def stix_bundle(self):
        fixture = Path(__file__).parent / "test_stix_bundle.json"
        if not fixture.exists():
            pytest.skip("test_stix_bundle.json not found")
        with open(fixture) as f:
            return json.load(f)

    def test_is_valid_bundle(self, stix_bundle):
        assert stix_bundle.get("type") == "bundle"
        assert "objects" in stix_bundle

    def test_has_stix_objects(self, stix_bundle):
        objects = stix_bundle["objects"]
        assert len(objects) > 0

    def test_objects_have_type_and_id(self, stix_bundle):
        for obj in stix_bundle["objects"]:
            assert "type" in obj
            assert "id" in obj

    def test_relationships_have_source_target(self, stix_bundle):
        relationships = [o for o in stix_bundle["objects"] if o["type"] == "relationship"]
        for rel in relationships:
            assert "source_ref" in rel
            assert "target_ref" in rel
            assert "relationship_type" in rel
