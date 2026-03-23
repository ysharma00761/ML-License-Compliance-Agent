"""
Integration tests — full scanner against demo-repo/

STUB — requires:
  - scanner/package_scanner.py (Person A, Task 2)
  - scanner/dataset_scanner.py (Person A, Task 4)
  - demo-repo/ populated with planted violations (Task 9)

CRITICAL CONSTRAINT: These tests are READ-ONLY against demo-repo/.
Never auto-fix violations. demo-repo/ must stay intentionally broken for the demo.
"""

import pytest
from pathlib import Path

DEMO_REPO = Path(__file__).parent.parent / "demo-repo"
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
    """Check if demo-repo has been populated."""
    return all((DEMO_REPO / f).exists() for f in REQUIRED_FILES)


@pytest.mark.skipif(not demo_repo_ready(), reason="demo-repo/ not yet populated (Task 9 pending)")
class TestFullScanAgainstDemoRepo:
    """
    End-to-end integration tests against the intentionally broken demo-repo.
    All expected violations must be found. Exit code must be 1.
    """

    @pytest.fixture(scope="class")
    def scan_results(self):
        # TODO: wire up once package_scanner and dataset_scanner exist
        # from scanner.model_scanner import scan as model_scan
        # from scanner.package_scanner import scan as pkg_scan
        # from scanner.dataset_scanner import scan as dataset_scan
        # from policy.engine import PolicyEngine
        # from output.bom_generator import generate
        pass

    def test_gpl_transitive_dep_detected(self, scan_results):
        """python-slugify → Unidecode (GPLv2+) must be flagged CRITICAL."""
        pytest.skip("Waiting for package_scanner.py (Task 2)")

    def test_llama_missing_attribution_detected(self, scan_results):
        """meta-llama/Meta-Llama-3-8B-Instruct without README attribution → HIGH."""
        pytest.skip("Waiting for demo-repo population (Task 9)")

    def test_llama_anti_distillation_detected(self, scan_results):
        """distill.py alongside Llama 3 → HIGH violation."""
        pytest.skip("Waiting for demo-repo population (Task 9)")

    def test_cc_by_nc_dataset_detected(self, scan_results):
        """lmsys/chatbot_arena_conversations (CC-BY-NC-4.0) → HIGH."""
        pytest.skip("Waiting for dataset_scanner.py (Task 4)")

    def test_agpl_saas_bomb_detected(self, scan_results):
        """ultralytics (AGPL-3.0) + FastAPI + Dockerfile → CRITICAL."""
        pytest.skip("Waiting for package_scanner.py (Task 2)")

    def test_exit_code_is_1(self, scan_results):
        """Pipeline must fail given the planted violations."""
        pytest.skip("Waiting for all scanners (Tasks 2, 4)")

    def test_bom_is_valid_cyclonedx_v1_5(self, scan_results):
        """ml-sbom.json must be valid CycloneDX 1.5."""
        pytest.skip("Waiting for all scanners (Tasks 2, 4)")

    def test_demo_repo_not_modified(self):
        """Verify demo-repo/ files are unchanged after scan — read-only constraint."""
        import subprocess
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD", "--", str(DEMO_REPO)],
            capture_output=True, text=True,
            cwd=DEMO_REPO.parent,
        )
        assert result.stdout.strip() == "", (
            f"demo-repo/ was modified during testing! Changed files:\n{result.stdout}"
        )
