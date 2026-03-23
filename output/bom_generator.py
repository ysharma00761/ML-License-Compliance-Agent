"""
CycloneDX ML-BOM Generator

Produces ml-sbom.json (CycloneDX v1.5) and compliance-report.md
from policy engine findings.
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression, LicenseRepository
from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.output.json import JsonV1Dot5
from packageurl import PackageURL

from policy.engine import PolicyFinding

logger = logging.getLogger(__name__)

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "WARNING":  "⚠️",
    "INFO":     "ℹ️",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 3, "INFO": 4}


# ---------------------------------------------------------------------------
# Component builders
# ---------------------------------------------------------------------------

def _make_license(license_id: Optional[str]) -> LicenseRepository:
    repo = LicenseRepository()
    if not license_id:
        return repo
    try:
        # Try as SPDX expression first
        repo.add(LicenseExpression(value=license_id))
    except Exception:
        # Fall back to named license
        repo.add(DisjunctiveLicense(name=license_id))
    return repo


def build_package_component(pkg_name: str, pkg_data: dict) -> Component:
    version = pkg_data.get("version", "unknown")
    license_id = pkg_data.get("license")

    try:
        purl = PackageURL(type="pypi", name=pkg_name.lower(), version=version)
    except Exception:
        purl = None

    return Component(
        type=ComponentType.LIBRARY,
        name=pkg_name,
        version=version,
        purl=purl,
        licenses=_make_license(license_id),
        description=f"PyPI package. License source: {pkg_data.get('license_source', 'deps.dev')}",
    )


def build_model_component(model_id: str, license_id: Optional[str],
                           license_category: Optional[str]) -> Component:
    parts = model_id.split("/")
    org = parts[0] if len(parts) == 2 else ""
    name = parts[-1]

    try:
        purl = PackageURL(type="huggingface", namespace=org, name=name)
    except Exception:
        purl = None

    description_parts = [f"Hugging Face model."]
    if license_category:
        description_parts.append(f"License category: {license_category}.")
    if license_category in ("RESTRICTED_USE", "CUSTOM_RESTRICTED"):
        description_parts.append(
            "This model has use restrictions that propagate to derivative works. Manual review required."
        )

    ext_refs = set()
    ext_refs.add(ExternalReference(
        type=ExternalReferenceType.OTHER,
        url=XsUri(f"https://huggingface.co/{model_id}"),
        comment="Hugging Face model card",
    ))

    return Component(
        type=ComponentType.MACHINE_LEARNING_MODEL,
        name=model_id,
        purl=purl,
        licenses=_make_license(license_id),
        description=" ".join(description_parts),
        external_references=ext_refs,
    )


def build_dataset_component(dataset_id: str, license_id: Optional[str],
                             commercial_eligible: Optional[bool]) -> Component:
    parts = dataset_id.split("/")
    org = parts[0] if len(parts) == 2 else ""
    name = parts[-1]

    try:
        purl = PackageURL(type="huggingface", namespace=org, name=name)
    except Exception:
        purl = None

    eligibility = "unknown"
    if commercial_eligible is True:
        eligibility = "yes"
    elif commercial_eligible is False:
        eligibility = "no — non-commercial license"

    ext_refs = set()
    ext_refs.add(ExternalReference(
        type=ExternalReferenceType.OTHER,
        url=XsUri(f"https://huggingface.co/datasets/{dataset_id}"),
        comment="Hugging Face dataset card",
    ))

    return Component(
        type=ComponentType.DATA,
        name=dataset_id,
        purl=purl,
        licenses=_make_license(license_id),
        description=f"Hugging Face dataset. Commercial use eligible: {eligibility}.",
        external_references=ext_refs,
    )


# ---------------------------------------------------------------------------
# BOM builder
# ---------------------------------------------------------------------------

def build_bom(
    findings: list[PolicyFinding],
    model_results: dict = None,
    dataset_results: dict = None,
    package_results: dict = None,
    project_name: str = "ml-project",
    project_version: str = "unknown",
) -> Bom:
    bom = Bom()
    bom.serial_number = uuid.uuid4()
    bom.metadata.timestamp = datetime.now(timezone.utc)

    # Tool attribution
    tool = Component(
        type=ComponentType.APPLICATION,
        name="ml-license-compliance-agent",
        version="1.0.0",
        description="GitLab AI Hackathon — ML License Compliance Agent. Powered by Anthropic Claude via GitLab Duo Agent Platform.",
    )
    bom.metadata.tools.components.add(tool)

    # Root component (the scanned project)
    bom.metadata.component = Component(
        type=ComponentType.APPLICATION,
        name=project_name,
        version=project_version,
    )

    # --- Add components ---
    seen_models = set()
    seen_datasets = set()
    seen_packages = set()

    if model_results:
        for mf in model_results.get("findings", []):
            if mf.model_id not in seen_models:
                seen_models.add(mf.model_id)
                bom.components.add(build_model_component(
                    mf.model_id, mf.license_id, mf.license_category
                ))

    if dataset_results:
        for df in dataset_results.get("findings", []):
            did = df.get("dataset_id", "")
            if did and did not in seen_datasets:
                seen_datasets.add(did)
                bom.components.add(build_dataset_component(
                    did,
                    df.get("license_id"),
                    df.get("commercial_eligible"),
                ))

    if package_results:
        for pkg_name, pkg_data in package_results.get("packages", {}).items():
            if pkg_name not in seen_packages:
                seen_packages.add(pkg_name)
                bom.components.add(build_package_component(pkg_name, pkg_data))

    return bom


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def write_bom_json(bom: Bom, output_path: Path) -> None:
    outputter = JsonV1Dot5(bom)
    json_str = outputter.output_as_string(indent=2)
    output_path.write_text(json_str)
    logger.info(f"Wrote CycloneDX ML-BOM to {output_path}")


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def write_compliance_report(
    findings: list[PolicyFinding],
    summary: dict,
    output_path: Path,
    project_name: str = "ml-project",
) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []

    lines.append(f"# ML License Compliance Report")
    lines.append(f"**Project:** {project_name}  ")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Agent:** ML License Compliance Agent (GitLab AI Hackathon)")
    lines.append("")

    # Executive summary
    exit_icon = "❌ FAILED" if (summary.get("critical", 0) + summary.get("high", 0)) > 0 else "✅ PASSED"
    lines.append(f"## Executive Summary")
    lines.append(f"**Status: {exit_icon}**")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "warning", "info"]:
        icon = SEVERITY_ICONS.get(sev.upper(), "•")
        lines.append(f"| {icon} {sev.upper()} | {summary.get(sev, 0)} |")
    lines.append("")

    if not findings:
        lines.append("No compliance issues found. ✅")
        output_path.write_text("\n".join(lines))
        return

    # Group by severity
    grouped: dict[str, list[PolicyFinding]] = {}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "INFO"]:
        group = grouped.get(sev, [])
        if not group:
            continue
        icon = SEVERITY_ICONS.get(sev, "•")
        lines.append(f"## {icon} {sev} ({len(group)})")
        lines.append("")

        for f in group:
            asset_label = {"package": "📦 Package", "model": "🤖 Model", "dataset": "📊 Dataset"}.get(f.asset_type, f.asset_type)
            lines.append(f"### {asset_label}: `{f.asset_name}`")
            lines.append(f"**Finding ID:** `{f.id}`  ")
            if f.license_id:
                lines.append(f"**License:** `{f.license_id}`  ")
            if f.source_file:
                lines.append(f"**Found in:** `{f.source_file}`  ")
            lines.append(f"**Violation:** {f.violation_type}  ")
            lines.append("")
            lines.append(f"> {f.detail}")
            lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
            lines.append("---")
            lines.append("")

    lines.append("## About This Report")
    lines.append(
        "Generated by the [ML License Compliance Agent](https://gitlab.com/gitlab-ai-hackathon) "
        "— the only tool that checks Python packages, Hugging Face models, and training datasets "
        "in a single CI/CD pass. Powered by Anthropic Claude via GitLab Duo Agent Platform."
    )

    output_path.write_text("\n".join(lines))
    logger.info(f"Wrote compliance report to {output_path}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate(
    findings: list[PolicyFinding],
    summary: dict,
    model_results: dict = None,
    dataset_results: dict = None,
    package_results: dict = None,
    project_name: str = "ml-project",
    project_version: str = "unknown",
    output_dir: Path = Path("."),
) -> dict:
    """
    Generate both output artifacts.
    Returns {"bom_path": Path, "report_path": Path}
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    bom_path = output_dir / "ml-sbom.json"
    report_path = output_dir / "compliance-report.md"

    bom = build_bom(
        findings=findings,
        model_results=model_results,
        dataset_results=dataset_results,
        package_results=package_results,
        project_name=project_name,
        project_version=project_version,
    )

    write_bom_json(bom, bom_path)
    write_compliance_report(findings, summary, report_path, project_name)

    return {"bom_path": bom_path, "report_path": report_path}
