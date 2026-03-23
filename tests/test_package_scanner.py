"""
Unit tests for scanner/package_scanner.py
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scanner.package_scanner import (
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_pipfile,
    collect_all_dependencies,
    resolve_license_deps_dev,
    resolve_license_pypi,
    normalize_license_text,
    detect_saas_context,
    scan,
)


class TestRequirementsParser:
    def test_parse_pinned_version(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("torch==2.1.0\nnumpy==1.24.0\n")
        result = parse_requirements_txt(req)
        assert result["torch"] == "==2.1.0"
        assert result["numpy"] == "==1.24.0"

    def test_parse_greater_than_equal(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("transformers>=4.30.0\n")
        result = parse_requirements_txt(req)
        assert result["transformers"] == ">=4.30.0"

    def test_parse_no_version(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests\nflask\n")
        result = parse_requirements_txt(req)
        assert result["requests"] == ""
        assert result["flask"] == ""

    def test_parse_multiple_requirements_files(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("torch==2.1.0\n")
        (tmp_path / "requirements-dev.txt").write_text("pytest==7.4.0\n")
        result = collect_all_dependencies(tmp_path)
        assert "torch" in result
        assert "pytest" in result

    def test_parse_pyproject_toml_dependencies(self, tmp_path):
        toml_content = """
[project]
dependencies = [
    "fastapi>=0.100",
    "uvicorn==0.23.0",
]
"""
        (tmp_path / "pyproject.toml").write_text(toml_content)
        result = parse_pyproject_toml(tmp_path / "pyproject.toml")
        assert "fastapi" in result
        assert "uvicorn" in result

    def test_parse_pipfile_packages(self, tmp_path):
        pipfile_content = """
[packages]
requests = "*"
flask = ">=2.0"

[dev-packages]
pytest = "*"
"""
        (tmp_path / "Pipfile").write_text(pipfile_content)
        result = parse_pipfile(tmp_path / "Pipfile")
        assert "requests" in result
        assert result["requests"] == ""
        assert "flask" in result
        assert "pytest" in result


class TestTransitiveDependencyResolution:
    def test_python_slugify_pulls_in_unidecode(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("python-slugify==8.0.1\n")
        with patch("scanner.package_scanner.resolve_transitive_deps", return_value={}), \
             patch("scanner.package_scanner._load_cache", return_value={}), \
             patch("scanner.package_scanner._save_cache"):
            result = scan(tmp_path)
        pkg = result["packages"]["python-slugify"]
        finding_types = [f["type"] for f in pkg["findings"]]
        assert "TRANSITIVE_GPL" in finding_types

    def test_transitive_gpl_flagged_as_critical(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("python-slugify==8.0.1\n")
        with patch("scanner.package_scanner.resolve_transitive_deps", return_value={}), \
             patch("scanner.package_scanner._load_cache", return_value={}), \
             patch("scanner.package_scanner._save_cache"):
            result = scan(tmp_path)
        pkg = result["packages"]["python-slugify"]
        gpl_findings = [f for f in pkg["findings"] if f["type"] == "TRANSITIVE_GPL"]
        assert gpl_findings[0]["severity"] == "CRITICAL"

    def test_direct_dep_chain_shown_in_output(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("python-slugify==8.0.1\n")
        with patch("scanner.package_scanner.resolve_transitive_deps", return_value={}), \
             patch("scanner.package_scanner._load_cache", return_value={}), \
             patch("scanner.package_scanner._save_cache"):
            result = scan(tmp_path)
        pkg = result["packages"]["python-slugify"]
        gpl_findings = [f for f in pkg["findings"] if f["type"] == "TRANSITIVE_GPL"]
        assert "Unidecode" in gpl_findings[0]["detail"]
        assert "python-slugify" in gpl_findings[0]["detail"]


class TestDepsDotDevApiParsing:
    def test_spdx_license_extracted(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"licenses": ["MIT"]}
        cache = {}
        with patch("scanner.package_scanner.requests.get", return_value=mock_resp):
            result = resolve_license_deps_dev("requests", "==2.31.0", cache)
        assert result["license"] == "MIT"
        assert result["source"] == "deps.dev"

    def test_fallback_to_pypi_json_on_failure(self):
        fail_resp = MagicMock()
        fail_resp.status_code = 500

        pypi_resp = MagicMock()
        pypi_resp.status_code = 200
        pypi_resp.json.return_value = {"info": {"license": "Apache-2.0"}}

        cache = {}
        with patch("scanner.package_scanner.requests.get", side_effect=[fail_resp, pypi_resp]):
            # deps.dev fails
            result1 = resolve_license_deps_dev("mypackage", "==1.0.0", cache)
            assert result1 is None
            # PyPI fallback succeeds
            result2 = resolve_license_pypi("mypackage", "==1.0.0", cache)
            assert result2["license"] == "Apache-2.0"
            assert result2["source"] == "pypi"

    def test_response_cached_locally(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"licenses": ["BSD-3-Clause"]}
        cache = {}
        with patch("scanner.package_scanner.requests.get", return_value=mock_resp) as mock_get:
            resolve_license_deps_dev("flask", "==2.3.0", cache)
            resolve_license_deps_dev("flask", "==2.3.0", cache)
            # Should only call the API once — second call hits cache
            assert mock_get.call_count == 1


class TestAgplSaasDetection:
    def test_ultralytics_plus_fastapi_is_critical(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("ultralytics==8.0.200\nfastapi\n")
        with patch("scanner.package_scanner.resolve_transitive_deps", return_value={}), \
             patch("scanner.package_scanner._load_cache", return_value={}), \
             patch("scanner.package_scanner._save_cache"):
            result = scan(tmp_path)
        pkg = result["packages"]["ultralytics"]
        agpl_findings = [f for f in pkg["findings"] if "AGPL" in f["type"]]
        assert any(f["severity"] == "CRITICAL" for f in agpl_findings)

    def test_ultralytics_without_saas_is_medium(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("ultralytics==8.0.200\n")
        with patch("scanner.package_scanner.resolve_transitive_deps", return_value={}), \
             patch("scanner.package_scanner._load_cache", return_value={}), \
             patch("scanner.package_scanner._save_cache"):
            result = scan(tmp_path)
        pkg = result["packages"]["ultralytics"]
        agpl_findings = [f for f in pkg["findings"] if "AGPL" in f["type"]]
        # Without SaaS indicators, should NOT be CRITICAL
        assert all(f["severity"] != "CRITICAL" for f in agpl_findings)

    def test_dockerfile_counts_as_saas_indicator(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("ultralytics==8.0.200\n")
        (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
        with patch("scanner.package_scanner.resolve_transitive_deps", return_value={}), \
             patch("scanner.package_scanner._load_cache", return_value={}), \
             patch("scanner.package_scanner._save_cache"):
            result = scan(tmp_path)
        pkg = result["packages"]["ultralytics"]
        agpl_findings = [f for f in pkg["findings"] if "AGPL" in f["type"]]
        assert any(f["severity"] == "CRITICAL" for f in agpl_findings)
