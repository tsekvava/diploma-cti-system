"""Tests for QueryEnricher — enrichment of short CTI queries from MITRE ATT&CK DB."""

import pytest




class TestDetectQueryType:

    def test_technique_id(self, enricher):
        detections = enricher.detect_query_type("T1059")
        types = [d["type"] for d in detections]
        assert "technique" in types

    def test_subtechnique_id(self, enricher):
        detections = enricher.detect_query_type("T1059.001")
        types = [d["type"] for d in detections]
        assert "technique" in types

    def test_tactic_id(self, enricher):
        detections = enricher.detect_query_type("TA0002")
        types = [d["type"] for d in detections]
        assert "tactic" in types

    def test_group_id(self, enricher):
        detections = enricher.detect_query_type("G0032")
        types = [d["type"] for d in detections]
        assert "group_id" in types

    def test_software_id(self, enricher):
        detections = enricher.detect_query_type("S0154")
        types = [d["type"] for d in detections]
        assert "software_id" in types

    def test_cve(self, enricher):
        detections = enricher.detect_query_type("CVE-2024-38063")
        types = [d["type"] for d in detections]
        assert "cve" in types

    def test_mitigation_id(self, enricher):
        detections = enricher.detect_query_type("M1036")
        types = [d["type"] for d in detections]
        assert "mitigation" in types

    def test_unknown_returns_empty(self, enricher):
        detections = enricher.detect_query_type("hello world")
        assert detections == [] or all(d["type"] not in ("technique", "group_id") for d in detections)




def _get_enrichment(result, etype=None):
    """Helper to extract enrichment data from result."""
    enrichments = result.get("enrichments", [])
    if not enrichments:
        return {}
    if etype:
        for e in enrichments:
            if e.get("type") == etype:
                return e
    return enrichments[0]


class TestEnrichTechnique:

    def test_t1059_basic(self, enricher):
        result = enricher.enrich("T1059")
        assert result is not None
        assert "technique" in result.get("detected", [{}])[0].get("type", "") or result.get("query_type") == "technique"
        assert "T1059" in result["query"]

    def test_t1059_has_subtechniques(self, enricher):
        result = enricher.enrich("T1059")
        data = _get_enrichment(result, "technique")
        subtechniques = data.get("subtechniques", [])
        assert len(subtechniques) >= 4

    def test_t1059_has_context(self, enricher):
        result = enricher.enrich("T1059")
        context = result.get("context_for_llm", "")
        assert len(context) > 100
        assert "T1059" in context

    def test_subtechnique_enrichment(self, enricher):
        result = enricher.enrich("T1059.001")
        assert result is not None
        data = _get_enrichment(result, "technique")
        assert data.get("found") is True




class TestEnrichGroup:

    def test_g0032_by_id(self, enricher):
        result = enricher.enrich("G0032")
        assert result is not None
        data = _get_enrichment(result, "group")
        assert data.get("found") is True

    def test_group_has_techniques(self, enricher):
        result = enricher.enrich("G0032")
        data = _get_enrichment(result, "group")
        techniques = data.get("techniques", [])
        assert len(techniques) > 0

    def test_group_has_software(self, enricher):
        result = enricher.enrich("G0032")
        data = _get_enrichment(result, "group")
        software = data.get("software", [])
        assert len(software) > 0

    def test_group_context_for_llm(self, enricher):
        result = enricher.enrich("G0032")
        context = result.get("context_for_llm", "")
        assert "Lazarus" in context or "G0032" in context




class TestEnrichSoftware:

    def test_s0154_by_id(self, enricher):
        result = enricher.enrich("S0154")
        assert result is not None
        data = _get_enrichment(result, "software")
        assert data.get("found") is True

    def test_software_has_techniques(self, enricher):
        result = enricher.enrich("S0154")
        data = _get_enrichment(result, "software")
        techniques = data.get("techniques", [])
        assert len(techniques) > 0




class TestNameBasedSearch:

    def test_group_by_name(self, enricher):
        result = enricher.enrich("Lazarus Group")
        assert result is not None
        context = result.get("context_for_llm", "")
        enrichments = result.get("enrichments", [])
        found = any(e.get("name") == "Lazarus Group" for e in enrichments) or "Lazarus" in context
        assert found

    def test_software_by_name(self, enricher):
        result = enricher.enrich("Cobalt Strike")
        assert result is not None




class TestEnrichCVE:

    def test_cve_detected(self, enricher):
        result = enricher.enrich("CVE-2024-38063")
        assert result is not None
        data = _get_enrichment(result, "cve")
        assert data.get("type") == "cve" or "cve" in str(result.get("detected", []))
