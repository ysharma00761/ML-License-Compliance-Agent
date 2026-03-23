"""
Unit tests for scanner/dataset_scanner.py
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scanner.dataset_scanner import (
    scan_python_files,
    _lookup_well_known,
    _classify_dataset,
    scan,
    WELL_KNOWN_DATASETS,
)


class TestDatasetReferenceExtraction:
    def test_single_arg_load_dataset(self, tmp_path):
        py_file = tmp_path / "train.py"
        py_file.write_text('from datasets import load_dataset\nds = load_dataset("squad")\n')
        resolved, unresolved = scan_python_files(tmp_path)
        assert "squad" in resolved

    def test_two_arg_load_dataset(self, tmp_path):
        py_file = tmp_path / "train.py"
        py_file.write_text('ds = load_dataset("glue", "mrpc", split="train")\n')
        resolved, unresolved = scan_python_files(tmp_path)
        assert "glue" in resolved

    def test_dynamic_dataset_reference_flagged_as_unresolved(self, tmp_path):
        py_file = tmp_path / "train.py"
        py_file.write_text('ds = load_dataset(dataset_name)\n')
        resolved, unresolved = scan_python_files(tmp_path)
        assert len(unresolved) == 1
        assert "dataset_name" in unresolved[0]["snippet"]

    def test_deduplication_across_files(self, tmp_path):
        (tmp_path / "train.py").write_text('ds = load_dataset("squad")\n')
        (tmp_path / "eval.py").write_text('ds = load_dataset("squad")\n')
        resolved, unresolved = scan_python_files(tmp_path)
        assert "squad" in resolved
        assert len(resolved["squad"]) == 2  # Both files listed


class TestDatasetLicenseResolution:
    def test_cc_by_nc_flagged_as_high(self):
        violations, warnings, eligible = _classify_dataset(
            "test/dataset", "cc-by-nc-4.0", None
        )
        assert any(v["severity"] == "HIGH" for v in violations)
        assert any(v["type"] == "NON_COMMERCIAL" for v in violations)
        assert eligible is False

    def test_cc_by_sa_flagged_as_medium(self):
        violations, warnings, eligible = _classify_dataset(
            "test/dataset", "cc-by-sa-4.0", None
        )
        assert any(w["severity"] == "MEDIUM" for w in warnings)
        assert any(w["type"] == "SHAREALIKE" for w in warnings)

    def test_missing_license_flagged_as_warning(self):
        violations, warnings, eligible = _classify_dataset(
            "test/dataset", None, None
        )
        assert any(w["severity"] == "WARNING" for w in warnings)
        assert any(w["type"] == "MISSING_LICENSE" for w in warnings)

    def test_well_known_dataset_registry_lookup(self):
        result = _lookup_well_known("lmsys/chatbot_arena_conversations")
        assert result is not None
        assert result["license"] == "CC-BY-NC-4.0"
        assert result["commercial_eligible"] is False


class TestWellKnownDatasetRegistry:
    def test_chatbot_arena_is_cc_by_nc(self):
        info = WELL_KNOWN_DATASETS["lmsys/chatbot_arena_conversations"]
        assert info["license"] == "CC-BY-NC-4.0"
        assert info["commercial_eligible"] is False

    def test_ffhq_is_cc_by_nc_sa(self):
        info = WELL_KNOWN_DATASETS["NVlabs/ffhq-dataset"]
        assert info["license"] == "CC-BY-NC-SA-4.0"
        assert info["commercial_eligible"] is False

    def test_wikipedia_is_cc_by_sa(self):
        info = WELL_KNOWN_DATASETS["wikipedia"]
        assert info["license"] == "CC-BY-SA-3.0"
        assert info["commercial_eligible"] is True
