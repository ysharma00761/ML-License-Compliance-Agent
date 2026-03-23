"""
Claude-Powered Compliance Analysis

Uses Anthropic Claude (via the Anthropic SDK) to enhance the compliance report with:
  1. Plain-English executive summary for non-legal engineers
  2. OpenRAIL use-restriction assessment tailored to the project
  3. Context-aware remediation priorities

Invoked from main.py when ANTHROPIC_API_KEY is set (or --anthropic-key is passed).
The GitLab Duo Agent (agents/agent.yml) provides the same Claude-powered analysis
interactively — this module powers the automated CI/CD path.
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_OPENRAIL_PROHIBITED = [
    "surveillance or tracking of individuals without consent",
    "military weapons targeting or autonomous weapons systems",
    "generating disinformation or coordinated inauthentic behavior",
    "discriminatory profiling based on protected characteristics",
    "predicting recidivism or parole decisions",
    "generating CSAM or sexual content involving minors",
]


def _format_findings_for_claude(
    findings: list,
    model_results: dict,
    dataset_results: dict,
    package_results: dict,
    project_name: str,
) -> str:
    """Build a compact findings summary to send to Claude."""
    lines = [f"# Compliance Scan: {project_name}\n"]

    # Summary counts
    severity_counts = {}
    for f in findings:
        sev = getattr(f, "severity", f.get("severity", "UNKNOWN")) if not hasattr(f, "severity") else f.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.append("## Finding Counts")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "INFO"]:
        if severity_counts.get(sev, 0):
            lines.append(f"- {sev}: {severity_counts[sev]}")

    # Individual findings
    lines.append("\n## Findings")
    for f in findings:
        sev = f.severity if hasattr(f, "severity") else f.get("severity", "?")
        vtype = f.violation_type if hasattr(f, "violation_type") else f.get("violation_type", "?")
        asset = f.asset_id if hasattr(f, "asset_id") else f.get("asset_id", "?")
        desc = f.description if hasattr(f, "description") else f.get("description", "")
        rem = f.remediation if hasattr(f, "remediation") else f.get("remediation", "")
        lines.append(f"- [{sev}] {vtype} | {asset}: {desc[:120]}")
        if rem:
            lines.append(f"  Fix: {rem[:100]}")

    # Project context
    lines.append("\n## Project Context")
    pkg_names = list(package_results.get("packages", {}).keys())[:10]
    if pkg_names:
        lines.append(f"Packages: {', '.join(pkg_names)}")

    model_ids = [f.model_id for f in model_results.get("findings", [])]
    if model_ids:
        lines.append(f"Models: {', '.join(model_ids)}")

    dataset_ids = [
        f.get("dataset_id", "")
        for f in dataset_results.get("findings", [])
        if not f.get("dataset_id", "").startswith("UNRESOLVED")
    ]
    if dataset_ids:
        lines.append(f"Datasets: {', '.join(dataset_ids)}")

    # Detect project type from packages
    saas_indicators = {"fastapi", "flask", "uvicorn", "gunicorn", "starlette", "django"}
    detected_saas = [p for p in pkg_names if p.lower() in saas_indicators]
    if detected_saas:
        lines.append(f"Deployment type: Web API / SaaS (detected: {', '.join(detected_saas)})")

    return "\n".join(lines)


def _has_openrail_models(model_results: dict) -> list:
    """Return list of OpenRAIL model IDs found in scan."""
    openrail_cats = {"RESTRICTED_USE"}
    return [
        f.model_id
        for f in model_results.get("findings", [])
        if getattr(f, "license_category", None) in openrail_cats
    ]


def analyze(
    findings: list,
    summary: dict,
    model_results: dict,
    dataset_results: dict,
    package_results: dict,
    project_name: str,
    api_key: Optional[str] = None,
) -> dict:
    """
    Run Claude analysis on scan results.

    Returns:
        {
            "executive_summary": str,   # Plain-English for non-legal audience
            "openrail_assessment": str | None,  # Only if OpenRAIL models found
            "top_priorities": str,      # Ordered remediation priorities
            "model_used": str,
        }
    """
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        logger.info("ANTHROPIC_API_KEY not set — skipping Claude analysis")
        return {}

    try:
        import anthropic
    except ImportError:
        logger.warning("anthropic package not installed — run: pip install anthropic")
        return {}

    client = anthropic.Anthropic(api_key=key)
    model = "claude-opus-4-6"
    results = {"model_used": model}

    findings_text = _format_findings_for_claude(
        findings, model_results, dataset_results, package_results, project_name
    )

    # -----------------------------------------------------------------------
    # 1. Executive summary — plain English for a non-legal engineer
    # -----------------------------------------------------------------------
    try:
        logger.info("Claude: generating executive summary...")
        with client.messages.stream(
            model=model,
            max_tokens=1024,
            thinking={"type": "adaptive"},
            system=(
                "You are a senior IP counsel who specializes in explaining ML license "
                "compliance to software engineers. Write clearly, avoid legal jargon, "
                "and focus on business risk and concrete next steps. Be concise."
            ),
            messages=[{
                "role": "user",
                "content": (
                    f"{findings_text}\n\n"
                    "Write a 3–5 sentence executive summary of this compliance scan for a "
                    "non-legal software engineer. Focus on: what the biggest risks are, "
                    "why they matter for the business, and what must be fixed before shipping. "
                    "Do not list every finding — synthesize the overall picture."
                ),
            }],
        ) as stream:
            results["executive_summary"] = stream.get_final_message().content[-1].text
    except Exception as e:
        logger.warning(f"Claude executive summary failed: {e}")
        results["executive_summary"] = None

    # -----------------------------------------------------------------------
    # 2. OpenRAIL assessment — only if relevant models detected
    # -----------------------------------------------------------------------
    openrail_models = _has_openrail_models(model_results)
    if openrail_models:
        try:
            logger.info(f"Claude: assessing OpenRAIL risks for {openrail_models}...")
            prohibited_text = "\n".join(f"- {u}" for u in _OPENRAIL_PROHIBITED)
            pkg_names = list(package_results.get("packages", {}).keys())
            project_desc = (
                f"Project: {project_name}\n"
                f"Models used: {', '.join(openrail_models)}\n"
                f"Packages: {', '.join(pkg_names[:15])}\n"
            )
            with client.messages.stream(
                model=model,
                max_tokens=512,
                system=(
                    "You are an ML license compliance expert. Assess whether a project "
                    "might conflict with OpenRAIL behavioral restrictions. Be specific "
                    "and practical. If risks are low, say so clearly."
                ),
                messages=[{
                    "role": "user",
                    "content": (
                        f"{project_desc}\n"
                        f"OpenRAIL prohibits:\n{prohibited_text}\n\n"
                        "Based on the project's packages and apparent purpose, does this "
                        "project risk violating any OpenRAIL restrictions? Give a 2–3 sentence "
                        "assessment with a clear LOW / MEDIUM / HIGH risk verdict."
                    ),
                }],
            ) as stream:
                results["openrail_assessment"] = stream.get_final_message().content[-1].text
        except Exception as e:
            logger.warning(f"Claude OpenRAIL assessment failed: {e}")
            results["openrail_assessment"] = None
    else:
        results["openrail_assessment"] = None

    # -----------------------------------------------------------------------
    # 3. Prioritised remediation roadmap
    # -----------------------------------------------------------------------
    try:
        logger.info("Claude: generating remediation priorities...")
        critical_count = summary.get("critical", 0)
        high_count = summary.get("high", 0)
        with client.messages.stream(
            model=model,
            max_tokens=768,
            system=(
                "You are a senior ML engineer advising a startup on license compliance. "
                "Give practical, actionable advice ordered by business impact. "
                "Be direct and use a numbered list."
            ),
            messages=[{
                "role": "user",
                "content": (
                    f"{findings_text}\n\n"
                    f"There are {critical_count} CRITICAL and {high_count} HIGH severity findings. "
                    "Give me a numbered list of the top 3–5 remediation steps, ordered by urgency. "
                    "For each step: what to do, how long it will roughly take, and what risk it eliminates."
                ),
            }],
        ) as stream:
            results["top_priorities"] = stream.get_final_message().content[-1].text
    except Exception as e:
        logger.warning(f"Claude remediation priorities failed: {e}")
        results["top_priorities"] = None

    return results
