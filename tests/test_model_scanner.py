"""
Unit tests for scanner/model_scanner.py

Covers: regex extraction, dynamic reference detection,
HF API response parsing (mocked), license taxonomy mapping,
Llama-specific checks, OpenRAIL flagging.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.model_scanner import (
    PY_MODEL_PATTERNS,
    PY_DYNAMIC_PATTERNS,
    LICENSE_TAXONOMY,
    scan_python_files,
    scan_config_files,
    resolve_model_license,
    check_llama_violations,
    flag_openrail,
    scan,
)


# ---------------------------------------------------------------------------
# Regex extraction
# ---------------------------------------------------------------------------

class TestPythonRegexExtraction:
    def _scan_source(self, source: str) -> tuple[dict, list]:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "model.py").write_text(source)
            return scan_python_files(root)

    def test_from_pretrained_basic(self):
        resolved, _ = self._scan_source(
            'model = AutoModelForCausalLM.from_pretrained("meta-llama/Meta-Llama-3-8B-Instruct")'
        )
        assert "meta-llama/Meta-Llama-3-8B-Instruct" in resolved

    def test_from_pretrained_tokenizer(self):
        resolved, _ = self._scan_source(
            'tok = AutoTokenizer.from_pretrained("bert-base-uncased")'
        )
        # bert-base-uncased has no slash — should not be captured as org/model
        assert "bert-base-uncased" not in resolved

    def test_from_pretrained_org_model(self):
        resolved, _ = self._scan_source(
            'model = AutoModel.from_pretrained("google/bert-base-uncased")'
        )
        assert "google/bert-base-uncased" in resolved

    def test_pipeline_model_kwarg(self):
        resolved, _ = self._scan_source(
            'pipe = pipeline("text-generation", model="openai-community/gpt2")'
        )
        assert "openai-community/gpt2" in resolved

    def test_sentence_transformer(self):
        resolved, _ = self._scan_source(
            'emb = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")'
        )
        assert "sentence-transformers/all-MiniLM-L6-v2" in resolved

    def test_deduplication_across_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "a.py").write_text(
                'AutoModel.from_pretrained("org/model-x")'
            )
            (root / "b.py").write_text(
                'AutoTokenizer.from_pretrained("org/model-x")'
            )
            resolved, _ = scan_python_files(root)
        assert "org/model-x" in resolved
        assert len(resolved["org/model-x"]) == 2  # found in both files

    def test_multiple_models_in_one_file(self):
        resolved, _ = self._scan_source(
            'AutoModel.from_pretrained("org/model-a")\n'
            'AutoModel.from_pretrained("org/model-b")\n'
        )
        assert "org/model-a" in resolved
        assert "org/model-b" in resolved

    def test_venv_files_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            venv = root / ".venv" / "lib"
            venv.mkdir(parents=True)
            (venv / "something.py").write_text(
                'AutoModel.from_pretrained("org/should-be-ignored")'
            )
            resolved, _ = scan_python_files(root)
        assert "org/should-be-ignored" not in resolved


class TestDynamicReferenceDetection:
    def _scan_source(self, source: str) -> tuple[dict, list]:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "model.py").write_text(source)
            return scan_python_files(root)

    def test_variable_reference_flagged_as_unresolved(self):
        _, unresolved = self._scan_source(
            "model = AutoModelForCausalLM.from_pretrained(model_name)"
        )
        assert len(unresolved) == 1
        assert "model_name" in unresolved[0]["snippet"]

    def test_fstring_reference_flagged_as_unresolved(self):
        _, unresolved = self._scan_source(
            'model = AutoModel.from_pretrained(f"{org}/{name}")'
        )
        assert len(unresolved) == 1

    def test_static_string_not_flagged_as_unresolved(self):
        _, unresolved = self._scan_source(
            'model = AutoModel.from_pretrained("org/model-name")'
        )
        assert len(unresolved) == 0


# ---------------------------------------------------------------------------
# License taxonomy
# ---------------------------------------------------------------------------

class TestLicenseTaxonomy:
    @pytest.mark.parametrize("license_id,expected_category", [
        ("apache-2.0", "PERMISSIVE"),
        ("mit", "PERMISSIVE"),
        ("bsd-3-clause", "PERMISSIVE"),
        ("gpl-3.0", "COPYLEFT_STRONG"),
        ("agpl-3.0", "COPYLEFT_STRONG"),
        ("gpl-2.0", "COPYLEFT_STRONG"),
        ("lgpl-2.1", "COPYLEFT_WEAK"),
        ("llama3", "CUSTOM_RESTRICTED"),
        ("llama2", "CUSTOM_RESTRICTED"),
        ("gemma", "CUSTOM_RESTRICTED"),
        ("openrail", "RESTRICTED_USE"),
        ("creativeml-openrail-m", "RESTRICTED_USE"),
        ("bigscience-bloom-rail-1.0", "RESTRICTED_USE"),
        ("cc-by-nc-4.0", "NON_COMMERCIAL"),
        ("cc-by-nc-sa-4.0", "NON_COMMERCIAL"),
        ("cc-by-sa-4.0", "SHARE_ALIKE"),
        ("other", "CUSTOM_REVIEW_REQUIRED"),
    ])
    def test_taxonomy_mapping(self, license_id, expected_category):
        assert LICENSE_TAXONOMY.get(license_id) == expected_category

    def test_unknown_license_not_in_taxonomy(self):
        assert "some-custom-license-xyz" not in LICENSE_TAXONOMY


# ---------------------------------------------------------------------------
# HF API response parsing (mocked)
# ---------------------------------------------------------------------------

class TestLicenseResolution:
    def test_license_from_tags(self):
        mock_info = MagicMock()
        mock_info.tags = ["license:apache-2.0", "transformers", "pytorch"]
        mock_info.cardData = {}

        with patch("scanner.model_scanner.HfApi") as MockApi:
            MockApi.return_value.model_info.return_value = mock_info
            cache = {}
            result = resolve_model_license("org/model", cache)

        assert result["license"] == "apache-2.0"

    def test_license_from_card_data_fallback(self):
        mock_info = MagicMock()
        mock_info.tags = ["transformers"]  # no license tag
        mock_info.cardData = {"license": "mit"}

        with patch("scanner.model_scanner.HfApi") as MockApi:
            MockApi.return_value.model_info.return_value = mock_info
            cache = {}
            result = resolve_model_license("org/model", cache)

        assert result["license"] == "mit"

    def test_license_other_extracts_name_and_link(self):
        mock_info = MagicMock()
        mock_info.tags = ["license:other"]
        mock_info.cardData = {
            "license": "other",
            "license_name": "Meta Llama 3 Community License",
            "license_link": "https://llama.meta.com/llama3/license/",
        }

        with patch("scanner.model_scanner.HfApi") as MockApi:
            MockApi.return_value.model_info.return_value = mock_info
            cache = {}
            result = resolve_model_license("meta-llama/Meta-Llama-3-8B", cache)

        assert result["license"] == "other"
        assert "Meta Llama" in result["license_name"]
        assert result["license_link"] is not None

    def test_private_model_flagged(self):
        from huggingface_hub.utils import RepositoryNotFoundError

        with patch("scanner.model_scanner.HfApi") as MockApi:
            MockApi.return_value.model_info.side_effect = RepositoryNotFoundError(
                "404", response=MagicMock(status_code=404)
            )
            cache = {}
            result = resolve_model_license("org/private-model", cache)

        assert result.get("error") == "private_or_not_found"

    def test_result_cached_on_second_call(self):
        mock_info = MagicMock()
        mock_info.tags = ["license:mit"]
        mock_info.cardData = {}

        with patch("scanner.model_scanner.HfApi") as MockApi:
            MockApi.return_value.model_info.return_value = mock_info
            cache = {}
            resolve_model_license("org/model", cache)
            resolve_model_license("org/model", cache)  # second call
            # API should only be called once due to cache
            assert MockApi.return_value.model_info.call_count == 1


# ---------------------------------------------------------------------------
# Llama-specific checks
# ---------------------------------------------------------------------------

class TestLlamaChecks:
    def test_missing_attribution_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # No README present
            violations, warnings = check_llama_violations(
                "meta-llama/Meta-Llama-3-8B-Instruct", root
            )
        violation_types = [v["type"] for v in violations]
        assert "MISSING_ATTRIBUTION" in violation_types

    def test_attribution_present_no_violation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text("Built with Meta Llama 3 for inference.")
            violations, _ = check_llama_violations(
                "meta-llama/Meta-Llama-3-8B-Instruct", root
            )
        violation_types = [v["type"] for v in violations]
        assert "MISSING_ATTRIBUTION" not in violation_types

    def test_distillation_script_flagged_for_llama3(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text("Built with Meta Llama 3")
            (root / "distill.py").write_text("# distillation script")
            violations, _ = check_llama_violations(
                "meta-llama/Meta-Llama-3-8B-Instruct", root
            )
        violation_types = [v["type"] for v in violations]
        assert "ANTI_DISTILLATION" in violation_types

    def test_distillation_not_flagged_for_llama31(self):
        """Llama 3.1+ relaxed the anti-distillation clause."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text("Built with Meta Llama 3")
            (root / "distill.py").write_text("# distillation script")
            violations, _ = check_llama_violations(
                "meta-llama/Meta-Llama-3.1-8B-Instruct", root
            )
        violation_types = [v["type"] for v in violations]
        assert "ANTI_DISTILLATION" not in violation_types

    def test_mau_threshold_always_present_as_info(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text("Built with Meta Llama 3")
            _, warnings = check_llama_violations(
                "meta-llama/Meta-Llama-3-8B-Instruct", root
            )
        warning_types = [w["type"] for w in warnings]
        assert "MAU_THRESHOLD" in warning_types
        mau = next(w for w in warnings if w["type"] == "MAU_THRESHOLD")
        assert mau["severity"] == "INFO"


# ---------------------------------------------------------------------------
# OpenRAIL flagging
# ---------------------------------------------------------------------------

class TestOpenRailFlagging:
    def test_all_prohibited_uses_flagged(self):
        warnings = flag_openrail("stabilityai/stable-diffusion-xl-base-1.0", "creativeml-openrail-m")
        assert len(warnings) == 6  # one per prohibited use case
        for w in warnings:
            assert w["severity"] == "MEDIUM"
            assert w["type"] == "OPENRAIL_USE_RESTRICTION"

    def test_flagging_mentions_propagation(self):
        warnings = flag_openrail("bigscience/bloom", "bigscience-bloom-rail-1.0")
        # At least one warning should mention derivatives
        assert any("derivative" in w["detail"].lower() for w in warnings)


# ---------------------------------------------------------------------------
# Full scan (mocked API)
# ---------------------------------------------------------------------------

class TestFullScan:
    def test_scan_produces_expected_structure(self):
        mock_info = MagicMock()
        mock_info.tags = ["license:llama3"]
        mock_info.cardData = {"license": "llama3"}

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "inference.py").write_text(
                'model = AutoModelForCausalLM.from_pretrained("meta-llama/Meta-Llama-3-8B-Instruct")'
            )

            with patch("scanner.model_scanner.HfApi") as MockApi:
                MockApi.return_value.model_info.return_value = mock_info
                results = scan(root)

        assert "findings" in results
        assert "unresolved" in results
        assert "summary" in results
        assert results["summary"]["total"] >= 1

    def test_scan_flags_agpl_model_as_critical(self):
        mock_info = MagicMock()
        mock_info.tags = ["license:agpl-3.0"]
        mock_info.cardData = {"license": "agpl-3.0"}

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "app.py").write_text(
                'model = AutoModel.from_pretrained("org/agpl-model")'
            )
            with patch("scanner.model_scanner.HfApi") as MockApi:
                MockApi.return_value.model_info.return_value = mock_info
                results = scan(root)

        critical = [f for f in results["findings"] if f.severity == "CRITICAL"]
        assert len(critical) >= 1

    def test_scan_missing_license_flagged_as_warning(self):
        mock_info = MagicMock()
        mock_info.tags = []
        mock_info.cardData = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "train.py").write_text(
                'model = AutoModel.from_pretrained("org/no-license-model")'
            )
            with patch("scanner.model_scanner.HfApi") as MockApi:
                MockApi.return_value.model_info.return_value = mock_info
                results = scan(root)

        warnings = [f for f in results["findings"] if f.severity == "WARNING"]
        assert len(warnings) >= 1
