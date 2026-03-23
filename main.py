"""
ML License Compliance Agent — main entry point

Runs all three scanners (packages, models, datasets), applies the policy engine,
generates CycloneDX ML-BOM and compliance report, and optionally posts MR comments.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from scanner.model_scanner import scan as model_scan
from scanner.package_scanner import scan as package_scan
from scanner.dataset_scanner import scan as dataset_scan
from scanner.claude_analyzer import analyze as claude_analyze
from policy.engine import PolicyEngine
from output.bom_generator import generate

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="ML License Compliance Scanner")
    parser.add_argument("--path", default=".", help="Path to repository to scan")
    parser.add_argument("--output-dir", default=".", help="Output directory for BOM and report")
    parser.add_argument("--policy", default=None, help="Path to compliance-policy.yml")
    parser.add_argument("--project-name", default="ml-project", help="Project name for BOM metadata")
    parser.add_argument("--project-version", default="unknown", help="Project version for BOM metadata")
    parser.add_argument("--skip-models", action="store_true", help="Skip model scanning")
    parser.add_argument("--skip-packages", action="store_true", help="Skip package scanning")
    parser.add_argument("--skip-datasets", action="store_true", help="Skip dataset scanning")
    parser.add_argument("--post-mr-comment", action="store_true", help="Post findings as GitLab MR comment")
    parser.add_argument("--claude-enhance", action="store_true", help="Enhance report with Claude AI analysis (requires ANTHROPIC_API_KEY)")
    parser.add_argument("--anthropic-key", default=None, help="Anthropic API key (overrides ANTHROPIC_API_KEY env var)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    repo_root = Path(args.path).resolve()
    hf_token = os.environ.get("HF_TOKEN")

    # ---- Run scanners ----
    logger.info(f"Scanning repository: {repo_root}")

    model_results = None
    package_results = None
    dataset_results = None

    if not args.skip_packages:
        logger.info("Running Python package scanner...")
        package_results = package_scan(repo_root)
        pkg_count = len(package_results.get("packages", {}))
        logger.info(f"  Found {pkg_count} packages")

    if not args.skip_models:
        logger.info("Running Hugging Face model scanner...")
        model_results = model_scan(repo_root, hf_token=hf_token)
        mdl_count = len(model_results.get("findings", []))
        logger.info(f"  Found {mdl_count} model references")

    if not args.skip_datasets:
        logger.info("Running training dataset scanner...")
        dataset_results = dataset_scan(repo_root, hf_token=hf_token)
        ds_count = len(dataset_results.get("findings", []))
        logger.info(f"  Found {ds_count} dataset references")

    # ---- Apply policy engine ----
    logger.info("Applying policy engine...")
    policy_path = Path(args.policy) if args.policy else None
    engine = PolicyEngine(policy_path) if policy_path else PolicyEngine()
    results = engine.evaluate(
        model_results=model_results,
        dataset_results=dataset_results,
        package_results=package_results,
    )

    # ---- Claude AI enhancement (optional) ----
    claude_analysis = {}
    if args.claude_enhance or args.anthropic_key or os.environ.get("ANTHROPIC_API_KEY"):
        logger.info("Running Claude-powered compliance analysis...")
        claude_analysis = claude_analyze(
            findings=results["findings"],
            summary=results["summary"],
            model_results=model_results or {"findings": []},
            dataset_results=dataset_results or {"findings": []},
            package_results=package_results or {"packages": {}},
            project_name=args.project_name,
            api_key=args.anthropic_key,
        )
        if claude_analysis.get("executive_summary"):
            logger.info("Claude analysis complete — executive summary added to report")

    # ---- Generate outputs ----
    output_dir = Path(args.output_dir)
    output_paths = generate(
        findings=results["findings"],
        summary=results["summary"],
        model_results=model_results,
        dataset_results=dataset_results,
        package_results=package_results,
        project_name=args.project_name,
        project_version=args.project_version,
        output_dir=output_dir,
        claude_analysis=claude_analysis,
    )

    # ---- Print summary ----
    s = results["summary"]
    status = "FAILED" if results["exit_code"] == 1 else "PASSED"
    print(f"\n{'=' * 60}")
    print(f"ML License Compliance Scan — {status}")
    print(f"{'=' * 60}")
    print(f"  CRITICAL: {s['critical']}")
    print(f"  HIGH:     {s['high']}")
    print(f"  MEDIUM:   {s['medium']}")
    print(f"  WARNING:  {s['warning']}")
    print(f"  INFO:     {s['info']}")
    print(f"  TOTAL:    {s['total']}")
    print(f"{'=' * 60}")
    print(f"BOM:    {output_paths['bom_path']}")
    print(f"Report: {output_paths['report_path']}")
    print()

    # ---- Post MR comment if requested ----
    if args.post_mr_comment:
        post_mr_comment(results)

    sys.exit(results["exit_code"])


# ---------------------------------------------------------------------------
# GitLab MR comment integration
# ---------------------------------------------------------------------------

SEVERITY_ICONS = {
    "CRITICAL": "\U0001f534",  # red circle
    "HIGH": "\U0001f7e0",      # orange circle
    "MEDIUM": "\U0001f7e1",    # yellow circle
    "WARNING": "\u26a0\ufe0f", # warning sign
    "INFO": "\u2139\ufe0f",    # info
}


def post_mr_comment(results: dict):
    """Post findings summary as a GitLab MR comment."""
    import requests

    mr_iid = os.environ.get("CI_MERGE_REQUEST_IID")
    project_id = os.environ.get("CI_PROJECT_ID")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    gitlab_url = os.environ.get("CI_SERVER_URL", "https://gitlab.com")

    if not all([mr_iid, project_id, gitlab_token]):
        logger.info("Not in MR context or missing GITLAB_TOKEN — skipping MR comment")
        return

    body = format_mr_comment(results)
    url = f"{gitlab_url}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"

    try:
        resp = requests.post(
            url,
            headers={"PRIVATE-TOKEN": gitlab_token},
            json={"body": body},
            timeout=15,
        )
        if resp.ok:
            logger.info(f"Posted MR comment to MR !{mr_iid}")
        else:
            logger.error(f"Failed to post MR comment: {resp.status_code} {resp.text}")
    except Exception as e:
        logger.error(f"Failed to post MR comment: {e}")


def format_mr_comment(results: dict) -> str:
    """Format findings as a collapsible Markdown MR comment."""
    s = results["summary"]
    status = "FAILED" if results["exit_code"] == 1 else "PASSED"

    lines = [
        f"## ML License Compliance Scan — {status}",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "INFO"]:
        icon = SEVERITY_ICONS.get(sev, "")
        lines.append(f"| {icon} {sev} | {s.get(sev.lower(), 0)} |")

    lines.append("")

    if results["findings"]:
        lines.append("<details><summary>Detailed Findings</summary>")
        lines.append("")

        for f in results["findings"]:
            icon = SEVERITY_ICONS.get(f.severity, "")
            lines.append(f"### {icon} [{f.severity}] {f.asset_type}: `{f.asset_name}`")
            lines.append(f"> {f.detail}")
            lines.append(f"")
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")

        lines.append("</details>")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by ML License Compliance Agent*")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
