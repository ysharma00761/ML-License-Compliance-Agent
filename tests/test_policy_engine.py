"""
Unit tests for policy/engine.py

Covers: severity classification, remediation lookup,
context flags (commercial_use, saas_deployment), exit code logic.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from policy.engine import PolicyEngine, PolicyFinding, REMEDIATION_LIBRARY
from scanner.model_scanner import ModelFinding


def _make_model_results(findings: list[ModelFinding], unresolved: list = None) -> dict:
    return {"findings": findings, "unresolved": unresolved or []}


def _default_engine(overrides: dict = None) -> PolicyEngine:
    """Create engine with a temp policy file, optionally overriding fields."""
    import yaml
    base = {
        "commercial_use": True,
        "saas_deployment": True,
        "require_attribution_check": True,
        "allowed_licenses": ["apache-2.0", "mit"],
        "denied_licenses": {"agpl-3.0": "CRITICAL", "gpl-3.0": "CRITICAL", "cc-by-nc-4.0": "HIGH"},
        "review_required_licenses": {"llama3": "HIGH", "openrail": "MEDIUM"},
        "fail_on": {"critical": True, "high": True, "medium": False, "warning": False},
    }
    if overrides:
        base.update(overrides)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        yaml.dump(base, f)
        return PolicyEngine(Path(f.name))


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

class TestSeverityClassification:
    def test_agpl_model_is_critical(self):
        mf = ModelFinding(
            model_id="org/agpl-model", source_file="app.py",
            license_id="agpl-3.0", license_category="COPYLEFT_STRONG",
            severity="CRITICAL",
            violations=[{"type": "COPYLEFT_STRONG", "severity": "CRITICAL",
                         "detail": "AGPL model in SaaS", "remediation": "Replace"}],
        )
        engine = _default_engine()
        findings = engine.process_model_findings(_make_model_results([mf]))
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_missing_llama_attribution_is_high(self):
        mf = ModelFinding(
            model_id="meta-llama/Meta-Llama-3-8B-Instruct", source_file="inference.py",
            license_id="llama3", license_category="CUSTOM_RESTRICTED",
            severity="HIGH",
            violations=[{"type": "MISSING_ATTRIBUTION", "severity": "HIGH",
                         "detail": "Missing attribution", "remediation": "Add to README"}],
        )
        engine = _default_engine()
        findings = engine.process_model_findings(_make_model_results([mf]))
        assert any(f.severity == "HIGH" and f.violation_type == "MISSING_ATTRIBUTION" for f in findings)

    def test_openrail_warning_is_medium(self):
        mf = ModelFinding(
            model_id="stabilityai/stable-diffusion-xl-base-1.0", source_file="gen.py",
            license_id="creativeml-openrail-m", license_category="RESTRICTED_USE",
            severity="MEDIUM",
            warnings=[{"type": "OPENRAIL_USE_RESTRICTION", "severity": "MEDIUM",
                       "detail": "Prohibited: surveillance", "remediation": "Review use cases"}],
        )
        engine = _default_engine()
        findings = engine.process_model_findings(_make_model_results([mf]))
        assert any(f.severity == "MEDIUM" for f in findings)

    def test_missing_license_is_warning(self):
        mf = ModelFinding(
            model_id="org/no-license", source_file="train.py",
            severity="WARNING",
            warnings=[{"type": "MISSING_LICENSE", "severity": "WARNING",
                       "detail": "No license", "remediation": "Check manually"}],
        )
        engine = _default_engine()
        findings = engine.process_model_findings(_make_model_results([mf]))
        assert any(f.severity == "WARNING" for f in findings)

    def test_permissive_model_produces_no_critical_or_high(self):
        mf = ModelFinding(
            model_id="google/bert-base-uncased", source_file="train.py",
            license_id="apache-2.0", license_category="PERMISSIVE",
            severity="INFO",
        )
        engine = _default_engine()
        findings = engine.process_model_findings(_make_model_results([mf]))
        assert not any(f.severity in ("CRITICAL", "HIGH") for f in findings)


# ---------------------------------------------------------------------------
# Context flags
# ---------------------------------------------------------------------------

class TestContextFlags:
    def test_nc_model_downgraded_when_not_commercial(self):
        mf = ModelFinding(
            model_id="org/nc-model", source_file="train.py",
            license_id="cc-by-nc-4.0", license_category="NON_COMMERCIAL",
            severity="HIGH",
            violations=[{"type": "NON_COMMERCIAL", "severity": "HIGH",
                         "detail": "NC license", "remediation": "Replace"}],
        )
        engine = _default_engine({"commercial_use": False})
        findings = engine.process_model_findings(_make_model_results([mf]))
        # Should be downgraded to INFO when not commercial
        assert not any(f.severity == "HIGH" for f in findings)

    def test_agpl_downgraded_when_not_saas(self):
        mf = ModelFinding(
            model_id="org/agpl-model", source_file="app.py",
            license_id="agpl-3.0", license_category="COPYLEFT_STRONG",
            severity="CRITICAL",
            violations=[{"type": "COPYLEFT_STRONG", "severity": "CRITICAL",
                         "detail": "AGPL SaaS", "remediation": "Replace"}],
        )
        engine = _default_engine({"saas_deployment": False})
        findings = engine.process_model_findings(_make_model_results([mf]))
        # AGPL downgraded to MEDIUM when not SaaS
        assert not any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# Unresolved references
# ---------------------------------------------------------------------------

class TestUnresolvedReferences:
    def test_unresolved_reference_becomes_warning(self):
        unresolved = [{"file": "train.py", "line": 5, "snippet": "from_pretrained(model_name)"}]
        engine = _default_engine()
        findings = engine.process_model_findings(_make_model_results([], unresolved))
        assert any(f.violation_type == "UNRESOLVED_REFERENCE" and f.severity == "WARNING"
                   for f in findings)


# ---------------------------------------------------------------------------
# Exit code logic
# ---------------------------------------------------------------------------

class TestExitCodeLogic:
    def test_exit_1_on_critical(self):
        mf = ModelFinding(
            model_id="org/gpl-model", source_file="app.py",
            license_id="gpl-3.0", license_category="COPYLEFT_STRONG",
            severity="CRITICAL",
            violations=[{"type": "COPYLEFT_STRONG", "severity": "CRITICAL",
                         "detail": "GPL", "remediation": "Replace"}],
        )
        engine = _default_engine()
        result = engine.evaluate(model_results=_make_model_results([mf]))
        assert result["exit_code"] == 1

    def test_exit_1_on_high_when_enabled(self):
        mf = ModelFinding(
            model_id="meta-llama/Meta-Llama-3-8B-Instruct", source_file="inf.py",
            license_id="llama3", license_category="CUSTOM_RESTRICTED",
            severity="HIGH",
            violations=[{"type": "MISSING_ATTRIBUTION", "severity": "HIGH",
                         "detail": "Missing", "remediation": "Add to README"}],
        )
        engine = _default_engine({"fail_on": {"critical": True, "high": True, "medium": False, "warning": False}})
        result = engine.evaluate(model_results=_make_model_results([mf]))
        assert result["exit_code"] == 1

    def test_exit_0_on_warning_only(self):
        mf = ModelFinding(
            model_id="org/no-license", source_file="train.py",
            severity="WARNING",
            warnings=[{"type": "MISSING_LICENSE", "severity": "WARNING",
                       "detail": "No license", "remediation": "Check"}],
        )
        engine = _default_engine()
        result = engine.evaluate(model_results=_make_model_results([mf]))
        assert result["exit_code"] == 0

    def test_exit_0_on_info_only(self):
        mf = ModelFinding(
            model_id="google/bert-base-uncased", source_file="train.py",
            license_id="apache-2.0", license_category="PERMISSIVE",
            severity="INFO",
        )
        engine = _default_engine()
        result = engine.evaluate(model_results=_make_model_results([mf]))
        assert result["exit_code"] == 0

    def test_findings_sorted_by_severity(self):
        findings_in = [
            ModelFinding(model_id="org/m1", source_file="a.py", severity="INFO",
                         warnings=[{"type": "T", "severity": "INFO", "detail": "d", "remediation": "r"}]),
            ModelFinding(model_id="org/m2", source_file="b.py", severity="CRITICAL",
                         violations=[{"type": "T", "severity": "CRITICAL", "detail": "d", "remediation": "r"}]),
            ModelFinding(model_id="org/m3", source_file="c.py", severity="WARNING",
                         warnings=[{"type": "T", "severity": "WARNING", "detail": "d", "remediation": "r"}]),
        ]
        engine = _default_engine()
        result = engine.evaluate(model_results=_make_model_results(findings_in))
        severities = [f.severity for f in result["findings"]]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 3, "INFO": 4}
        assert severities == sorted(severities, key=lambda s: order.get(s, 99))


# ---------------------------------------------------------------------------
# Remediation library
# ---------------------------------------------------------------------------

class TestRemediationLibrary:
    @pytest.mark.parametrize("asset_name,expected_substring", [
        ("ultralytics", "Enterprise"),
        ("Unidecode", "text-unidecode"),
        ("PyQt5", "PySide2"),
        ("PyQt6", "PySide6"),
    ])
    def test_known_remediations_present(self, asset_name, expected_substring):
        engine = _default_engine()
        text = engine._get_remediation("COPYLEFT_STRONG", asset_name)
        assert expected_substring in text
