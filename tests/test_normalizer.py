"""Tests for EntityNormalizer — 3-level entity matching against MITRE ATT&CK."""

import pytest




class TestNormalizeThreatActor:
    """Tests for normalize_threat_actor()."""

    def test_exact_match(self, normalizer):
        result = normalizer.normalize_threat_actor("Lazarus Group")
        assert result["normalized"] is True
        assert result["mitre_id"] == "G0032"
        assert result["match_type"] == "exact"
        assert result["confidence_bonus"] == 10

    def test_exact_match_case_insensitive(self, normalizer):
        result = normalizer.normalize_threat_actor("lazarus group")
        assert result["normalized"] is True
        assert result["mitre_id"] == "G0032"
        assert result["match_type"] == "exact"

    def test_alias_match(self, normalizer):
        result = normalizer.normalize_threat_actor("HIDDEN COBRA")
        assert result["normalized"] is True
        assert result["mitre_id"] == "G0032"
        assert result["match_type"] == "alias"
        assert result["confidence_bonus"] == 5

    def test_mitre_id_as_alias(self, normalizer):
        result = normalizer.normalize_threat_actor("G0032")
        assert result["normalized"] is True
        assert result["mitre_id"] == "G0032"

    def test_fuzzy_match(self, normalizer):
        result = normalizer.normalize_threat_actor("Lazarus Grp")
        assert result["normalized"] is True
        assert result["mitre_id"] == "G0032"
        assert result["match_type"] == "fuzzy"
        assert result["match_score"] >= 85
        assert result["confidence_bonus"] == 0

    def test_not_found(self, normalizer):
        result = normalizer.normalize_threat_actor("SuperNewAPT9000")
        assert result["normalized"] is False
        assert result["mitre_id"] is None
        assert result["match_type"] == "none"
        assert result["confidence_bonus"] == -10

    def test_apt28_by_alias(self, normalizer):
        result = normalizer.normalize_threat_actor("Fancy Bear")
        assert result["normalized"] is True
        assert result["name"] == "APT28"

    def test_original_preserved(self, normalizer):
        result = normalizer.normalize_threat_actor("HIDDEN COBRA")
        assert result["original"] == "HIDDEN COBRA"

    def test_whitespace_stripped(self, normalizer):
        result = normalizer.normalize_threat_actor("  Lazarus Group  ")
        assert result["normalized"] is True
        assert result["mitre_id"] == "G0032"




class TestNormalizeSoftware:
    """Tests for normalize_software()."""

    def test_exact_match(self, normalizer):
        result = normalizer.normalize_software("Cobalt Strike")
        assert result["normalized"] is True
        assert result["mitre_id"] == "S0154"
        assert result["match_type"] == "exact"
        assert result["type"] in ("tool", "malware")

    def test_exact_match_case_insensitive(self, normalizer):
        result = normalizer.normalize_software("mimikatz")
        assert result["normalized"] is True
        assert result["match_type"] == "exact"

    def test_mitre_id_as_alias(self, normalizer):
        result = normalizer.normalize_software("S0154")
        assert result["normalized"] is True
        assert result["name"] == "Cobalt Strike"

    def test_not_found(self, normalizer):
        result = normalizer.normalize_software("NotARealMalware")
        assert result["normalized"] is False
        assert result["mitre_id"] is None
        assert result["confidence_bonus"] == -10

    def test_result_has_type_field(self, normalizer):
        result = normalizer.normalize_software("Mimikatz")
        assert "type" in result
        assert result["type"] in ("malware", "tool")




class TestValidateTechniqueId:
    """Tests for validate_technique_id()."""

    def test_valid_technique(self, normalizer):
        info = normalizer.validate_technique_id("T1059")
        assert info is not None
        assert info["id"] == "T1059"
        assert info["name_en"] != ""

    def test_valid_subtechnique(self, normalizer):
        info = normalizer.validate_technique_id("T1059.001")
        assert info is not None
        assert info["is_subtechnique"] is True

    def test_invalid_technique(self, normalizer):
        info = normalizer.validate_technique_id("T9999")
        assert info is None

    def test_hallucinated_subtechnique(self, normalizer):
        info = normalizer.validate_technique_id("T1010.004")
        assert info is None

    def test_case_insensitive_id(self, normalizer):
        info = normalizer.validate_technique_id("t1059")
        assert info is not None

    def test_technique_has_russian_name(self, normalizer):
        info = normalizer.validate_technique_id("T1059")
        assert info["name_ru"] != ""




class TestGetTechniquesForTactic:

    def test_returns_list(self, normalizer):
        techs = normalizer.get_techniques_for_tactic("TA0002")
        assert isinstance(techs, list)
        assert len(techs) > 0

    def test_execution_has_t1059(self, normalizer):
        techs = normalizer.get_techniques_for_tactic("TA0002")
        ids = [t["id"] for t in techs]
        assert "T1059" in ids

    def test_nonexistent_tactic_returns_empty(self, normalizer):
        techs = normalizer.get_techniques_for_tactic("TA9999")
        assert techs == []




class TestNormalizeAll:

    def test_deduplicates_actors(self, normalizer):
        data = {
            "threat_actor": ["Lazarus Group", "HIDDEN COBRA", "lazarus group"],
            "malware": [],
            "tools": [],
        }
        result = normalizer.normalize_all(data)
        assert len(result["threat_actor"]) == 1
        assert result["threat_actor"][0]["mitre_id"] == "G0032"

    def test_preserves_ioc(self, normalizer):
        data = {
            "threat_actor": [],
            "malware": [],
            "tools": [],
            "indicators": {"ipv4": ["1.2.3.4"], "domain": ["evil.com"]},
        }
        result = normalizer.normalize_all(data)
        assert result["indicators"]["ipv4"] == ["1.2.3.4"]

    def test_empty_input(self, normalizer):
        result = normalizer.normalize_all({})
        assert result["threat_actor"] == []
        assert result["malware"] == []
        assert result["tools"] == []
