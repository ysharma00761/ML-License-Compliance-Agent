"""
Unit tests for output/bom_generator.py

Covers: CycloneDX v1.5 structure, component types,
purl format, markdown report generation.
"""

import json
import tempfile
from pathlib import Path

import pytest

from output.bom_generator import (
    build_package_component,
    build_model_component,
    build_dataset_component,
    build_bom,
    write_bom_json,
    write_compliance_report,
    generate,
)
from policy.engine import PolicyFinding


def _make_finding(severity="HIGH", asset_type="model", asset_name="org/model",
                  violation_type="TEST", detail="test detail", remediation="fix it",
                  license_id="llama3", source_file="train.py") -> PolicyFinding:
    return PolicyFinding(
        id=f"TST-0001",
        severity=severity,
        asset_type=asset_type,
        asset_name=asset_name,
        violation_type=violation_type,
        detail=detail,
        remediation=remediation,
        license_id=license_id,
        source_file=source_file,
    )


# ---------------------------------------------------------------------------
# Component builders
# ---------------------------------------------------------------------------

class TestComponentBuilders:
    def test_package_component_type_is_library(self):
        from cyclonedx.model.component import ComponentType
        comp = build_package_component("requests", {"version": "2.31.0", "license": "apache-2.0"})
        assert comp.type == ComponentType.LIBRARY

    def test_package_component_purl_format(self):
        comp = build_package_component("requests", {"version": "2.31.0", "license": "apache-2.0"})
        assert comp.purl is not None
        assert "pypi" in str(comp.purl).lower()
        assert "requests" in str(comp.purl).lower()

    def test_model_component_type_is_ml_model(self):
        from cyclonedx.model.component import ComponentType
        comp = build_model_component("meta-llama/Meta-Llama-3-8B-Instruct", "llama3", "CUSTOM_RESTRICTED")
        assert comp.type == ComponentType.MACHINE_LEARNING_MODEL

    def test_model_component_purl_format(self):
        comp = build_model_component("meta-llama/Meta-Llama-3-8B-Instruct", "llama3", "CUSTOM_RESTRICTED")
        assert "huggingface" in str(comp.purl).lower()

    def test_model_component_has_external_ref(self):
        comp = build_model_component("meta-llama/Meta-Llama-3-8B-Instruct", "llama3", "CUSTOM_RESTRICTED")
        assert len(comp.external_references) > 0
        urls = [str(ref.url) for ref in comp.external_references]
        assert any("huggingface.co" in u for u in urls)

    def test_model_component_restricted_use_note_in_description(self):
        comp = build_model_component("org/model", "openrail", "RESTRICTED_USE")
        assert "restriction" in comp.description.lower() or "review" in comp.description.lower()

    def test_dataset_component_type_is_data(self):
        from cyclonedx.model.component import ComponentType
        comp = build_dataset_component("lmsys/chatbot_arena_conversations", "cc-by-nc-4.0", False)
        assert comp.type == ComponentType.DATA

    def test_dataset_component_commercial_ineligible_in_description(self):
        comp = build_dataset_component("NVlabs/ffhq-dataset", "cc-by-nc-sa-4.0", False)
        assert "non-commercial" in comp.description.lower()

    def test_dataset_component_has_external_ref(self):
        comp = build_dataset_component("lmsys/chatbot_arena_conversations", "cc-by-nc-4.0", False)
        urls = [str(ref.url) for ref in comp.external_references]
        assert any("huggingface.co" in u for u in urls)


# ---------------------------------------------------------------------------
# BOM structure
# ---------------------------------------------------------------------------

class TestBomStructure:
    def _serialize(self, bom) -> dict:
        from cyclonedx.output.json import JsonV1Dot5
        return json.loads(JsonV1Dot5(bom).output_as_string())

    def test_spec_version_is_1_5(self):
        bom = build_bom([], project_name="test")
        data = self._serialize(bom)
        assert data["specVersion"] == "1.5"

    def test_bom_format_is_cyclonedx(self):
        bom = build_bom([], project_name="test")
        data = self._serialize(bom)
        assert data["bomFormat"] == "CycloneDX"

    def test_metadata_timestamp_present(self):
        bom = build_bom([], project_name="test")
        data = self._serialize(bom)
        assert "timestamp" in data["metadata"]

    def test_metadata_tools_present(self):
        bom = build_bom([], project_name="test")
        data = self._serialize(bom)
        tools = data["metadata"].get("tools", {})
        assert tools  # non-empty

    def test_model_component_appears_in_bom(self):
        from scanner.model_scanner import ModelFinding as MF
        mf = MF(model_id="org/test-model", source_file="train.py",
                license_id="apache-2.0", license_category="PERMISSIVE", severity="INFO")
        model_results = {"findings": [mf], "unresolved": []}
        bom = build_bom([], model_results=model_results, project_name="test")
        data = self._serialize(bom)
        names = [c["name"] for c in data.get("components", [])]
        assert "org/test-model" in names

    def test_serial_number_is_uuid(self):
        import re
        bom = build_bom([], project_name="test")
        data = self._serialize(bom)
        sn = data.get("serialNumber", "")
        assert re.match(r"urn:uuid:[0-9a-f-]{36}", sn)


# ---------------------------------------------------------------------------
# BOM JSON file output
# ---------------------------------------------------------------------------

class TestBomJsonOutput:
    def test_json_file_written(self):
        bom = build_bom([], project_name="test")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "ml-sbom.json"
            write_bom_json(bom, path)
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["specVersion"] == "1.5"

    def test_json_is_valid_json(self):
        bom = build_bom([], project_name="test")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "ml-sbom.json"
            write_bom_json(bom, path)
            # Should not raise
            json.loads(path.read_text())


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

class TestMarkdownReport:
    def test_report_file_written(self):
        findings = [_make_finding(severity="CRITICAL")]
        summary = {"total": 1, "critical": 1, "high": 0, "medium": 0, "warning": 0, "info": 0}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "compliance-report.md"
            write_compliance_report(findings, summary, path, project_name="test")
            assert path.exists()

    def test_report_contains_critical_section(self):
        findings = [_make_finding(severity="CRITICAL", detail="GPL contamination")]
        summary = {"total": 1, "critical": 1, "high": 0, "medium": 0, "warning": 0, "info": 0}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "compliance-report.md"
            write_compliance_report(findings, summary, path)
            content = path.read_text()
        assert "CRITICAL" in content
        assert "GPL contamination" in content

    def test_report_executive_summary_shows_failed(self):
        findings = [_make_finding(severity="CRITICAL")]
        summary = {"total": 1, "critical": 1, "high": 0, "medium": 0, "warning": 0, "info": 0}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "compliance-report.md"
            write_compliance_report(findings, summary, path)
            content = path.read_text()
        assert "FAILED" in content

    def test_report_executive_summary_shows_passed(self):
        summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "warning": 0, "info": 0}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "compliance-report.md"
            write_compliance_report([], summary, path)
            content = path.read_text()
        assert "PASSED" in content

    def test_report_contains_remediation(self):
        findings = [_make_finding(remediation="Replace with text-unidecode")]
        summary = {"total": 1, "critical": 0, "high": 1, "medium": 0, "warning": 0, "info": 0}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "compliance-report.md"
            write_compliance_report(findings, summary, path)
            content = path.read_text()
        assert "text-unidecode" in content

    def test_report_grouped_by_severity_order(self):
        findings = [
            _make_finding(severity="WARNING", asset_name="org/warn-model"),
            _make_finding(severity="CRITICAL", asset_name="org/crit-model"),
        ]
        summary = {"total": 2, "critical": 1, "high": 0, "medium": 0, "warning": 1, "info": 0}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "compliance-report.md"
            write_compliance_report(findings, summary, path)
            content = path.read_text()
        # CRITICAL section should appear before WARNING section
        assert content.index("CRITICAL") < content.index("WARNING")


# ---------------------------------------------------------------------------
# End-to-end generate()
# ---------------------------------------------------------------------------

class TestGenerateFunction:
    def test_both_files_created(self):
        findings = [_make_finding()]
        summary = {"total": 1, "critical": 0, "high": 1, "medium": 0, "warning": 0, "info": 0}
        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate(findings, summary, output_dir=Path(tmpdir))
            assert result["bom_path"].exists()
            assert result["report_path"].exists()
