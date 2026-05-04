"""Tests for benchmark metric calculations."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "benchmark"))

from benchmark_multi_model import (
    calculate_f1_set,
    normalize_entity,
    get_entity_set,
    get_ioc_set,
    get_attack_pattern_set,
    _extract_mitre_ids,
)




class TestCalculateF1Set:

    def test_perfect_match(self):
        p, r, f1 = calculate_f1_set({"a", "b"}, {"a", "b"})
        assert p == 1.0
        assert r == 1.0
        assert f1 == 1.0

    def test_no_overlap(self):
        p, r, f1 = calculate_f1_set({"a", "b"}, {"c", "d"})
        assert p == 0.0
        assert r == 0.0
        assert f1 == 0.0

    def test_partial_overlap(self):
        p, r, f1 = calculate_f1_set({"a", "b", "c"}, {"a", "b", "d"})
        # TP=2, FP=1, FN=1 → P=2/3, R=2/3, F1=2/3
        assert abs(p - 0.6667) < 0.01
        assert abs(r - 0.6667) < 0.01
        assert abs(f1 - 0.6667) < 0.01

    def test_empty_truth(self):
        p, r, f1 = calculate_f1_set({"a"}, set())
        assert f1 == 0.0

    def test_empty_pred(self):
        p, r, f1 = calculate_f1_set(set(), {"a"})
        assert p == 0.0
        assert r == 0.0
        assert f1 == 0.0

    def test_both_empty(self):
        p, r, f1 = calculate_f1_set(set(), set())
        assert f1 == 0.0

    def test_all_false_positives(self):
        p, r, f1 = calculate_f1_set({"x", "y"}, {"a", "b"})
        assert p == 0.0
        assert r == 0.0

    def test_superset_prediction(self):
        p, r, f1 = calculate_f1_set({"a", "b", "c"}, {"a", "b"})
        # TP=2, FP=1, FN=0 → P=2/3, R=1.0
        assert abs(r - 1.0) < 0.01
        assert abs(p - 0.6667) < 0.01




class TestNormalizeEntity:

    def test_lowercase(self):
        assert normalize_entity("APT28") == "apt28"

    def test_strip_whitespace(self):
        assert normalize_entity("  Lazarus Group  ") == "lazarus group"

    def test_removes_mitre_id(self):
        result = normalize_entity("Phishing (T1566)")
        assert "t1566" not in result
        assert "phishing" in result

    def test_removes_cve(self):
        result = normalize_entity("Exploit (CVE-2024-12345)")
        assert "cve-2024-12345" not in result

    def test_strips_punctuation(self):
        result = normalize_entity("(Cobalt Strike)")
        assert result == "cobalt strike"




class TestExtractMitreIds:

    def test_plain_id(self):
        ids = _extract_mitre_ids(["T1566"])
        assert "t1566" in ids

    def test_subtechnique_id(self):
        ids = _extract_mitre_ids(["T1566.001"])
        assert "t1566.001" in ids

    def test_id_in_parentheses(self):
        ids = _extract_mitre_ids(["Spearphishing Attachment (T1566.001)"])
        assert "t1566.001" in ids

    def test_multiple_ids_in_one_string(self):
        ids = _extract_mitre_ids(["T1059 and T1059.001"])
        assert "t1059" in ids
        assert "t1059.001" in ids

    def test_no_ids(self):
        ids = _extract_mitre_ids(["Phishing", "Malware"])
        assert len(ids) == 0

    def test_empty_list(self):
        ids = _extract_mitre_ids([])
        assert len(ids) == 0




class TestGetEntitySet:

    def test_basic(self):
        data = {"threat_actor": ["APT28", "Lazarus Group"]}
        s = get_entity_set(data, ["threat_actor"])
        assert "apt28" in s
        assert "lazarus group" in s

    def test_filters_short_strings(self):
        data = {"threat_actor": ["AB", "APT28"]}
        s = get_entity_set(data, ["threat_actor"])
        assert "ab" not in s  # len <= 2 filtered
        assert "apt28" in s

    def test_missing_key(self):
        data = {}
        s = get_entity_set(data, ["threat_actor"])
        assert len(s) == 0




class TestGetIocSet:

    def test_extracts_all_types(self):
        data = {
            "indicators": {
                "ipv4": ["1.2.3.4"],
                "domain": ["evil.com"],
                "hash": ["abc123"],
            }
        }
        s = get_ioc_set(data)
        assert "1.2.3.4" in s
        assert "evil.com" in s
        assert "abc123" in s

    def test_empty_indicators(self):
        s = get_ioc_set({"indicators": {}})
        assert len(s) == 0

    def test_no_indicators_key(self):
        s = get_ioc_set({})
        assert len(s) == 0




class TestGetAttackPatternSet:

    def test_mitre_ids_extracted(self):
        data = {"attack_patterns": ["T1566.001", "T1059"]}
        s = get_attack_pattern_set(data)
        assert "t1566.001" in s
        assert "t1059" in s

    def test_text_names_when_no_id(self):
        data = {"attack_patterns": ["phishing", "credential dumping"]}
        s = get_attack_pattern_set(data)
        assert "phishing" in s
        assert "credential dumping" in s

    def test_mixed_ids_and_names(self):
        data = {"attack_patterns": [
            "Spearphishing Attachment (T1566.001)",
            "credential dumping",
        ]}
        s = get_attack_pattern_set(data)
        assert "t1566.001" in s
        assert "credential dumping" in s

    def test_empty(self):
        s = get_attack_pattern_set({})
        assert len(s) == 0
