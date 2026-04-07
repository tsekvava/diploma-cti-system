"""
Tests for InputLoader — multi-format report file loading.

Tests cover:
  - Plain text loading (txt, md, log)
  - HTML parsing (tag stripping)
  - LoadedReport dataclass fields
  - Error handling for missing files
  - Extension detection
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from summarizer.input_loader import (
    load_report_file,
    LoadedReport,
    InputLoadError,
    TEXT_EXTENSIONS,
    HTML_EXTENSIONS,
    PDF_EXTENSIONS,
    DOCX_EXTENSIONS,
    IMAGE_EXTENSIONS,
)


# ── Extension sets ───────────────────────────────────────


class TestExtensionSets:

    def test_text_extensions(self):
        assert ".txt" in TEXT_EXTENSIONS
        assert ".md" in TEXT_EXTENSIONS
        assert ".log" in TEXT_EXTENSIONS

    def test_html_extensions(self):
        assert ".html" in HTML_EXTENSIONS
        assert ".htm" in HTML_EXTENSIONS

    def test_pdf_extensions(self):
        assert ".pdf" in PDF_EXTENSIONS

    def test_docx_extensions(self):
        assert ".docx" in DOCX_EXTENSIONS

    def test_image_extensions(self):
        assert ".png" in IMAGE_EXTENSIONS
        assert ".jpg" in IMAGE_EXTENSIONS


# ── Text file loading ────────────────────────────────────


class TestLoadTextFile:

    def test_load_txt(self, tmp_path):
        f = tmp_path / "report.txt"
        f.write_text("APT28 attacked using Cobalt Strike.", encoding="utf-8")
        result = load_report_file(str(f))
        assert isinstance(result, LoadedReport)
        assert "APT28" in result.text
        assert result.input_format == "txt"

    def test_load_md(self, tmp_path):
        f = tmp_path / "report.md"
        f.write_text("# Threat Report\nLazarus used Mimikatz.", encoding="utf-8")
        result = load_report_file(str(f))
        assert "Lazarus" in result.text
        assert result.input_format == "md"

    def test_empty_file_raises(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("", encoding="utf-8")
        with pytest.raises(InputLoadError):
            load_report_file(str(f))

    def test_utf8_russian(self, tmp_path):
        f = tmp_path / "report.txt"
        f.write_text("Группировка APT28 атаковала объекты КИИ.", encoding="utf-8")
        result = load_report_file(str(f))
        assert "APT28" in result.text
        assert "КИИ" in result.text


# ── HTML file loading ────────────────────────────────────


class TestLoadHTMLFile:

    def test_strips_tags(self, tmp_path):
        f = tmp_path / "report.html"
        f.write_text(
            "<html><body><h1>Threat</h1><p>APT28 used <b>Cobalt Strike</b>.</p></body></html>",
            encoding="utf-8",
        )
        result = load_report_file(str(f))
        assert "APT28" in result.text
        assert "<html>" not in result.text
        assert result.input_format == "html"


# ── Error handling ───────────────────────────────────────


class TestErrorHandling:

    def test_file_not_found(self):
        with pytest.raises((InputLoadError, FileNotFoundError, OSError)):
            load_report_file("/nonexistent/path/report.txt")

    def test_unsupported_extension(self, tmp_path):
        f = tmp_path / "report.xyz"
        f.write_text("some data", encoding="utf-8")
        with pytest.raises((InputLoadError, ValueError, KeyError)):
            load_report_file(str(f))


# ── LoadedReport dataclass ───────────────────────────────


class TestLoadedReport:

    def test_has_required_fields(self, tmp_path):
        f = tmp_path / "report.txt"
        f.write_text("test content", encoding="utf-8")
        result = load_report_file(str(f))
        assert hasattr(result, "text")
        assert hasattr(result, "input_format")

    def test_text_is_string(self, tmp_path):
        f = tmp_path / "report.txt"
        f.write_text("test", encoding="utf-8")
        result = load_report_file(str(f))
        assert isinstance(result.text, str)


# ── Sample report loading ────────────────────────────────


class TestSampleReports:
    """Test loading actual sample reports from the project."""

    def test_load_gold_salem(self):
        path = Path(__file__).parent.parent / "benchmark" / "data" / "gold_salem.txt"
        if not path.exists():
            pytest.skip("gold_salem.txt not found")
        result = load_report_file(str(path))
        assert len(result.text) > 1000
        assert result.input_format == "txt"

    def test_load_sample_html(self):
        path = Path(__file__).parent.parent / "data" / "sample_report_gold_salem.html"
        if not path.exists():
            pytest.skip("sample_report_gold_salem.html not found")
        result = load_report_file(str(path))
        assert len(result.text) > 100
        assert result.input_format in ("html", "htm")
