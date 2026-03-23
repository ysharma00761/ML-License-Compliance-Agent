"""
Integration tests — full scanner against demo-repo/

CRITICAL CONSTRAINT: These tests are READ-ONLY against demo-repo/.
Never auto-fix violations. demo-repo/ must stay intentionally broken for the demo.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from scanner.model_scanner import scan as model_scan
from scanner.package_scanner import scan as package_scan
from scanner.dataset_scanner import scan as dataset_scan
from policy.engine import PolicyEngine
from output.bom_generator import generate

DEMO_REPO = Path(__file__).parent.parent / "demo-repo"
POLICY_PATH = Path(__file__).parent.parent / "policy" / "compliance-policy.yml"

REQUIRED_FILES = [
    "requirements.txt",
    "inference.py",
    "train_data.py",
    "distill.py",
    "detect.py",
    "app.py",
    "Dockerfile",
]


def demo_repo_ready():
    return all((DEMO_REPO / f).exists() for f in REQUIRED_FILES)


# ---------------------------------------------------------------------------
# Shared scan fixture — runs all scanners once for the whole class
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def full_scan_results():
    """
    Run all three scanners + policy engine against demo-repo/.
    Mocks the HF API so tests don't require network access.
    """
    def _mock_model_info(model_id, *args, **kwargs):
        mock = MagicMock()
        licenses = {
            "meta-llama/Meta-Llama-3-8B-Instruct": "llama3",
            "stabilityai/stable-diffusion-xl-base-1.0": "creativeml-openrail-m",
        }
        license_id = licenses.get(model_id, "apache-2.0")
        mock.tags = [f"license:{license_id}"]
        mock.cardData = {"license": license_id}
        return mock

    def _mock_dataset_info(dataset_id, *args, **kwargs):
        mock = MagicMock()
        licenses = {
            "lmsys/chatbot_arena_conversations": "cc-by-nc-4.0",
        }
        license_id = licenses.get(dataset_id, "apache-2.0")
        mock.tags = [f"license:{license_id}"]
        mock.cardData = {"license": license_id}
        return mock

    with patch("scanner.model_scanner.HfApi") as MockModelApi, \
         patch("scanner.dataset_scanner.HfApi") as MockDatasetApi, \
         patch("scanner.package_scanner.resolve_transitive_deps", return_value={}), \
         patch("scanner.package_scanner._load_cache", return_value={}), \
         patch("scanner.package_scanner._save_cache"):

        MockModelApi.return_value.model_info.side_effect = _mock_model_info
        MockDatasetApi.return_value.dataset_info.side_effect = _mock_dataset_info

        model_results = model_scan(DEMO_REPO)
        package_results = package_scan(DEMO_REPO)
        dataset_results = dataset_scan(DEMO_REPO)

    engine = PolicyEngine(POLICY_PATH)
    policy_results = engine.evaluate(
        model_results=model_results,
        dataset_results=dataset_results,
        package_results=package_results,
    )

    return {
        "model": model_results,
        "package": package_results,
        "dataset": dataset_results,
        "policy": policy_results,
    }


# ---------------------------------------------------------------------------
# Demo scenario 1: Hidden GPL trap
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not demo_repo_ready(), reason="demo-repo/ not populated")
class TestGPLTrap:
    def test_python_slugify_detected(self, full_scan_results):
        packages = full_scan_results["package"]["packages"]
        assert "python-slugify" in packages

    def test_unidecode_transitive_gpl_flagged(self, full_scan_results):
        packages = full_scan_results["package"]["packages"]
        pkg = packages["python-slugify"]
        finding_types = [f["type"] for f in pkg["findings"]]
        assert "TRANSITIVE_GPL" in finding_types

    def test_unidecode_is_critical(self, full_scan_results):
        packages = full_scan_results["package"]["packages"]
        pkg = packages["python-slugify"]
        gpl = [f for f in pkg["findings"] if f["type"] == "TRANSITIVE_GPL"]
        assert gpl[0]["severity"] == "CRITICAL"

    def test_remediation_mentions_text_unidecode(self, full_scan_results):
        packages = full_scan_results["package"]["packages"]
        pkg = packages["python-slugify"]
        gpl = [f for f in pkg["findings"] if f["type"] == "TRANSITIVE_GPL"]
        assert "text-unidecode" in gpl[0]["remediation"]


# ---------------------------------------------------------------------------
# Demo scenario 2: LLaMA triple violation
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not demo_repo_ready(), reason="demo-repo/ not populated")
class TestLlamaTripleViolation:
    def test_llama_model_detected(self, full_scan_results):
        model_ids = [f.model_id for f in full_scan_results["model"]["findings"]]
        assert "meta-llama/Meta-Llama-3-8B-Instruct" in model_ids

    def test_missing_attribution_flagged(self, full_scan_results):
        findings = full_scan_results["policy"]["findings"]
        types = [f.violation_type for f in findings]
        assert "MISSING_ATTRIBUTION" in types

    def test_missing_attribution_is_high(self, full_scan_results):
        findings = full_scan_results["policy"]["findings"]
        attr = [f for f in findings if f.violation_type == "MISSING_ATTRIBUTION"]
        assert attr[0].severity == "HIGH"

    def test_anti_distillation_flagged(self, full_scan_results):
        findings = full_scan_results["policy"]["findings"]
        types = [f.violation_type for f in findings]
        assert "ANTI_DISTILLATION" in types

    def test_cc_by_nc_dataset_flagged(self, full_scan_results):
        findings = full_scan_results["policy"]["findings"]
        nc = [f for f in findings if f.violation_type == "NON_COMMERCIAL" and f.asset_type == "dataset"]
        assert len(nc) >= 1

    def test_cc_by_nc_dataset_is_high(self, full_scan_results):
        findings = full_scan_results["policy"]["findings"]
        nc = [f for f in findings if f.violation_type == "NON_COMMERCIAL" and f.asset_type == "dataset"]
        assert nc[0].severity == "HIGH"


# ---------------------------------------------------------------------------
# Demo scenario 3: AGPL SaaS bomb
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not demo_repo_ready(), reason="demo-repo/ not populated")
class TestAgplSaasBomb:
    def test_ultralytics_detected(self, full_scan_results):
        packages = full_scan_results["package"]["packages"]
        assert "ultralytics" in packages

    def test_agpl_saas_is_critical(self, full_scan_results):
        packages = full_scan_results["package"]["packages"]
        pkg = packages["ultralytics"]
        agpl = [f for f in pkg["findings"] if "AGPL" in f["type"]]
        assert any(f["severity"] == "CRITICAL" for f in agpl)

    def test_remediation_mentions_enterprise_or_alternative(self, full_scan_results):
        packages = full_scan_results["package"]["packages"]
        pkg = packages["ultralytics"]
        agpl = [f for f in pkg["findings"] if "AGPL" in f["type"]]
        text = agpl[0]["remediation"].lower()
        assert "enterprise" in text or "rt-detr" in text


# ---------------------------------------------------------------------------
# Exit code and BOM
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not demo_repo_ready(), reason="demo-repo/ not populated")
class TestExitCodeAndBom:
    def test_exit_code_is_1(self, full_scan_results):
        assert full_scan_results["policy"]["exit_code"] == 1

    def test_has_critical_findings(self, full_scan_results):
        assert full_scan_results["policy"]["summary"]["critical"] >= 1

    def test_has_high_findings(self, full_scan_results):
        assert full_scan_results["policy"]["summary"]["high"] >= 1

    def test_bom_is_valid_cyclonedx_v1_5(self, full_scan_results):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate(
                findings=full_scan_results["policy"]["findings"],
                summary=full_scan_results["policy"]["summary"],
                model_results=full_scan_results["model"],
                dataset_results=full_scan_results["dataset"],
                package_results=full_scan_results["package"],
                project_name="demo-repo",
                output_dir=Path(tmpdir),
            )
            bom = json.loads(result["bom_path"].read_text())
            assert bom["specVersion"] == "1.5"
            assert bom["bomFormat"] == "CycloneDX"
            assert len(bom.get("components", [])) >= 1

    def test_compliance_report_generated(self, full_scan_results):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate(
                findings=full_scan_results["policy"]["findings"],
                summary=full_scan_results["policy"]["summary"],
                model_results=full_scan_results["model"],
                dataset_results=full_scan_results["dataset"],
                package_results=full_scan_results["package"],
                project_name="demo-repo",
                output_dir=Path(tmpdir),
            )
            report = result["report_path"].read_text()
            assert "CRITICAL" in report
            assert "FAILED" in report


# ---------------------------------------------------------------------------
# Demo-repo integrity check
# ---------------------------------------------------------------------------

class TestDemoRepoIntegrity:
    def test_demo_repo_not_modified(self):
        """Verify demo-repo/ files are unchanged — read-only constraint."""
        import subprocess
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD", "--", str(DEMO_REPO)],
            capture_output=True, text=True,
            cwd=DEMO_REPO.parent,
        )
        assert result.stdout.strip() == "", (
            f"demo-repo/ was modified during testing!\n{result.stdout}"
        )

    @pytest.mark.skipif(not demo_repo_ready(), reason="demo-repo/ not populated")
    def test_all_required_files_present(self):
        for f in REQUIRED_FILES:
            assert (DEMO_REPO / f).exists(), f"Missing demo-repo/{f}"

    @pytest.mark.skipif(not demo_repo_ready(), reason="demo-repo/ not populated")
    def test_violations_still_present(self):
        """Confirm no one accidentally fixed the demo violations."""
        req = (DEMO_REPO / "requirements.txt").read_text()
        assert "python-slugify" in req, "GPL trap removed from requirements.txt"
        assert "ultralytics" in req, "AGPL package removed from requirements.txt"

        inference = (DEMO_REPO / "inference.py").read_text()
        assert "meta-llama" in inference, "Llama model reference removed from inference.py"

        train = (DEMO_REPO / "train_data.py").read_text()
        assert "chatbot_arena_conversations" in train, "NC dataset removed from train_data.py"

        distill = (DEMO_REPO / "distill.py").read_text()
        assert len(distill) > 100, "distill.py was emptied"
