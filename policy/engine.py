"""
Policy Engine

Takes raw findings from all scanners, applies the compliance policy,
and produces a severity-ranked, deduplicated findings list with
remediation steps and a CI/CD exit code.
"""

import sys
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATH = Path(__file__).parent / "compliance-policy.yml"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 3, "INFO": 4}

# ---------------------------------------------------------------------------
# Remediation library — specific fixes for known violation types
# ---------------------------------------------------------------------------

REMEDIATION_LIBRARY = {
    # Package-level
    "Unidecode": (
        "Replace `python-slugify` with a version that uses `text-unidecode` instead of `Unidecode`: "
        "`pip install text-unidecode` and set `pip install python-slugify` with the `unidecode` extra removed. "
        "Or replace `python-slugify` entirely with `python-slugify[unidecode]` pinned to `text-unidecode`."
    ),
    "ultralytics": (
        "AGPL-3.0 requires full source disclosure for SaaS/network use. Options: "
        "(1) Purchase Ultralytics Enterprise License at ultralytics.com/license, or "
        "(2) Replace with RT-DETR (Apache-2.0): `pip install rtdetr`."
    ),
    "PyQt5": (
        "Replace `PyQt5` (GPL-3.0) with `PySide2` (LGPL-2.1) — same Qt5 API, commercially safe. "
        "`pip install PySide2`"
    ),
    "PyQt6": (
        "Replace `PyQt6` (GPL-3.0) with `PySide6` (LGPL-2.1) — same Qt6 API, commercially safe. "
        "`pip install PySide6`"
    ),
    # Model-level
    "MISSING_ATTRIBUTION": (
        "Add 'Built with Meta Llama 3' to your README.md and all user-facing documentation "
        "as required by the Meta Llama 3 Community License §2.3."
    ),
    "ANTI_DISTILLATION": (
        "Llama 3 (not 3.1+) prohibits using model outputs to train competing LLMs (§1.b.v). "
        "Options: (1) Switch to Llama 3.1+ where this clause is relaxed, or "
        "(2) Remove training scripts that consume Llama outputs."
    ),
    "NON_COMMERCIAL_MODEL": (
        "This model's license prohibits commercial use. "
        "Replace with a commercially licensed alternative (Apache-2.0 or MIT models on Hugging Face Hub)."
    ),
    "AGPL_SAAS": (
        "AGPL-3.0 §13 requires full source code disclosure for network/SaaS deployments. "
        "Options: (1) Open-source your entire application under AGPL-3.0, or "
        "(2) Obtain a commercial license from the model/package vendor."
    ),
    # Dataset-level
    "CC_BY_NC_COMMERCIAL": (
        "This dataset is licensed CC-BY-NC which prohibits commercial use. "
        "Replace with a permissively licensed alternative. "
        "Search for CC-BY-4.0 or Apache-2.0 datasets on Hugging Face Hub."
    ),
    "CC_BY_SA_SHAREALIKE": (
        "CC-BY-SA requires derivative works to use the same license. "
        "Consult legal on whether your model constitutes a derivative work. "
        "If unsure, replace with a CC-BY-4.0 or Apache-2.0 licensed dataset."
    ),
    # Generic fallbacks
    "COPYLEFT_STRONG": (
        "This license requires all distributed derivative works to be open-sourced under the same license. "
        "Obtain a commercial license from the vendor or replace with an Apache-2.0/MIT alternative."
    ),
    "MISSING_LICENSE": (
        "No license found — treat as All Rights Reserved. "
        "Contact the author for clarification or replace with a clearly licensed alternative."
    ),
    "UNKNOWN_LICENSE": (
        "Unrecognized license — manual legal review required before commercial use."
    ),
    "OPENRAIL_USE_RESTRICTION": (
        "Review your application against all OpenRAIL prohibited use cases. "
        "These restrictions propagate to all fine-tuned derivatives. Consult legal if any prohibited use case applies."
    ),
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PolicyFinding:
    id: str
    severity: str
    asset_type: str          # "package", "model", "dataset"
    asset_name: str
    violation_type: str
    detail: str
    remediation: str
    source_file: Optional[str] = None
    license_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------

def load_policy(policy_path: Path = DEFAULT_POLICY_PATH) -> dict:
    with open(policy_path) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    def __init__(self, policy_path: Path = DEFAULT_POLICY_PATH):
        self.policy = load_policy(policy_path)
        self._finding_counter = 0

    def _next_id(self, prefix: str) -> str:
        self._finding_counter += 1
        return f"{prefix}-{self._finding_counter:04d}"

    def _get_remediation(self, violation_type: str, asset_name: str) -> str:
        # Try exact asset name match first (e.g. "ultralytics", "PyQt5")
        for key, text in REMEDIATION_LIBRARY.items():
            if key.lower() in asset_name.lower():
                return text
        # Fall back to violation type
        return REMEDIATION_LIBRARY.get(violation_type, "Consult legal counsel before proceeding.")

    def _severity_from_policy(self, license_id: str) -> Optional[str]:
        """Check if a license ID is in denied or review_required lists."""
        denied = self.policy.get("denied_licenses", {})
        review = self.policy.get("review_required_licenses", {})
        lid = license_id.lower()
        if lid in {k.lower() for k in denied}:
            for k, v in denied.items():
                if k.lower() == lid:
                    return v
        if lid in {k.lower() for k in review}:
            for k, v in review.items():
                if k.lower() == lid:
                    return v
        return None

    # ------------------------------------------------------------------
    # Process model scanner output
    # ------------------------------------------------------------------

    def process_model_findings(self, model_results: dict) -> list[PolicyFinding]:
        findings = []
        commercial = self.policy.get("commercial_use", True)
        saas = self.policy.get("saas_deployment", True)

        for mf in model_results.get("findings", []):
            # Violations from the scanner (Llama attribution, distillation, AGPL, NC)
            for v in mf.violations:
                sev = v.get("severity", "HIGH")
                # Downgrade NC violations if not commercial
                if v.get("type") == "NON_COMMERCIAL" and not commercial:
                    sev = "INFO"
                # Downgrade AGPL if not SaaS
                if v.get("type") == "COPYLEFT_STRONG" and not saas:
                    sev = "MEDIUM"

                findings.append(PolicyFinding(
                    id=self._next_id("MDL"),
                    severity=sev,
                    asset_type="model",
                    asset_name=mf.model_id,
                    violation_type=v.get("type", "UNKNOWN"),
                    detail=v.get("detail", ""),
                    remediation=v.get("remediation") or self._get_remediation(v.get("type", ""), mf.model_id),
                    source_file=mf.source_file,
                    license_id=mf.license_id,
                ))

            # Warnings from the scanner
            for w in mf.warnings:
                sev = w.get("severity", "WARNING")
                findings.append(PolicyFinding(
                    id=self._next_id("MDL"),
                    severity=sev,
                    asset_type="model",
                    asset_name=mf.model_id,
                    violation_type=w.get("type", "UNKNOWN"),
                    detail=w.get("detail", ""),
                    remediation=w.get("remediation") or self._get_remediation(w.get("type", ""), mf.model_id),
                    source_file=mf.source_file,
                    license_id=mf.license_id,
                ))

            # Private/missing model
            if mf.private_or_missing:
                findings.append(PolicyFinding(
                    id=self._next_id("MDL"),
                    severity="WARNING",
                    asset_type="model",
                    asset_name=mf.model_id,
                    violation_type="PRIVATE_OR_MISSING",
                    detail=f'"{mf.model_id}" not found on Hugging Face Hub — license unknown.',
                    remediation=self._get_remediation("MISSING_LICENSE", mf.model_id),
                    source_file=mf.source_file,
                ))

        # Unresolved dynamic references
        for u in model_results.get("unresolved", []):
            findings.append(PolicyFinding(
                id=self._next_id("MDL"),
                severity="WARNING",
                asset_type="model",
                asset_name="[dynamic reference]",
                violation_type="UNRESOLVED_REFERENCE",
                detail=f'Dynamic model reference cannot be resolved automatically: {u["file"]}:{u["line"]} — `{u["snippet"]}`',
                remediation="Replace with a hardcoded string literal or document the model license manually.",
                source_file=u["file"],
            ))

        return findings

    # ------------------------------------------------------------------
    # Process dataset scanner output
    # ------------------------------------------------------------------

    def process_dataset_findings(self, dataset_results: dict) -> list[PolicyFinding]:
        findings = []
        commercial = self.policy.get("commercial_use", True)

        for df in dataset_results.get("findings", []):
            for v in df.get("violations", []):
                sev = v.get("severity", "HIGH")
                if "NON_COMMERCIAL" in v.get("type", "") and not commercial:
                    sev = "INFO"
                findings.append(PolicyFinding(
                    id=self._next_id("DAT"),
                    severity=sev,
                    asset_type="dataset",
                    asset_name=df.get("dataset_id", "unknown"),
                    violation_type=v.get("type", "UNKNOWN"),
                    detail=v.get("detail", ""),
                    remediation=v.get("remediation") or self._get_remediation(v.get("type", ""), df.get("dataset_id", "")),
                    source_file=df.get("source_file"),
                    license_id=df.get("license_id"),
                ))

            for w in df.get("warnings", []):
                findings.append(PolicyFinding(
                    id=self._next_id("DAT"),
                    severity=w.get("severity", "WARNING"),
                    asset_type="dataset",
                    asset_name=df.get("dataset_id", "unknown"),
                    violation_type=w.get("type", "UNKNOWN"),
                    detail=w.get("detail", ""),
                    remediation=w.get("remediation") or self._get_remediation(w.get("type", ""), df.get("dataset_id", "")),
                    source_file=df.get("source_file"),
                    license_id=df.get("license_id"),
                ))

        return findings

    # ------------------------------------------------------------------
    # Process package scanner output
    # ------------------------------------------------------------------

    def process_package_findings(self, package_results: dict) -> list[PolicyFinding]:
        findings = []
        saas = self.policy.get("saas_deployment", True)

        for pkg_name, pkg_data in package_results.get("packages", {}).items():
            for finding in pkg_data.get("findings", []):
                sev = finding.get("severity", "WARNING")
                vtype = finding.get("type", "UNKNOWN")

                # Downgrade AGPL if not SaaS
                if "AGPL" in vtype and not saas:
                    sev = "MEDIUM"

                findings.append(PolicyFinding(
                    id=self._next_id("PKG"),
                    severity=sev,
                    asset_type="package",
                    asset_name=pkg_name,
                    violation_type=vtype,
                    detail=finding.get("detail", ""),
                    remediation=finding.get("remediation") or self._get_remediation(vtype, pkg_name),
                    license_id=pkg_data.get("license"),
                ))

        return findings

    # ------------------------------------------------------------------
    # Combine and rank all findings
    # ------------------------------------------------------------------

    def evaluate(
        self,
        model_results: dict = None,
        dataset_results: dict = None,
        package_results: dict = None,
    ) -> dict:
        all_findings: list[PolicyFinding] = []

        if model_results:
            all_findings.extend(self.process_model_findings(model_results))
        if dataset_results:
            all_findings.extend(self.process_dataset_findings(dataset_results))
        if package_results:
            all_findings.extend(self.process_package_findings(package_results))

        # Sort by severity
        all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 4))

        # Summary counts
        summary = {"total": len(all_findings), "critical": 0, "high": 0, "medium": 0, "warning": 0, "info": 0}
        for f in all_findings:
            key = f.severity.lower()
            if key in summary:
                summary[key] += 1

        # Exit code
        fail_on = self.policy.get("fail_on", {})
        exit_code = 0
        if summary["critical"] > 0 and fail_on.get("critical", True):
            exit_code = 1
        elif summary["high"] > 0 and fail_on.get("high", True):
            exit_code = 1

        return {
            "findings": all_findings,
            "summary": summary,
            "exit_code": exit_code,
            "policy": self.policy,
        }


# ---------------------------------------------------------------------------
# Exit helper for CI/CD
# ---------------------------------------------------------------------------

def run_and_exit(model_results=None, dataset_results=None, package_results=None,
                 policy_path=DEFAULT_POLICY_PATH):
    engine = PolicyEngine(policy_path)
    results = engine.evaluate(
        model_results=model_results,
        dataset_results=dataset_results,
        package_results=package_results,
    )

    s = results["summary"]
    print(f"\n=== Policy Engine Results ===")
    print(f"CRITICAL: {s['critical']} | HIGH: {s['high']} | MEDIUM: {s['medium']} | "
          f"WARNING: {s['warning']} | INFO: {s['info']}")
    print(f"Exit code: {results['exit_code']}")

    for f in results["findings"]:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "WARNING": "⚠️", "INFO": "ℹ️"}.get(f.severity, "•")
        print(f"\n{icon} [{f.severity}] {f.asset_type.upper()}: {f.asset_name}")
        print(f"   {f.detail}")
        print(f"   → {f.remediation}")

    sys.exit(results["exit_code"])
