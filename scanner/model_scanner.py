"""
Hugging Face Model License Scanner

Scans a repository for HF model references, resolves their licenses
via the HF Hub API, and flags compliance violations.
"""

import os
import re
import json
import time
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from huggingface_hub import HfApi
from huggingface_hub.utils import RepositoryNotFoundError, HfHubHTTPError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# License taxonomy — maps HF license identifiers to compliance categories
# ---------------------------------------------------------------------------

LICENSE_TAXONOMY = {
    # Permissive
    "apache-2.0":       "PERMISSIVE",
    "mit":              "PERMISSIVE",
    "bsd-2-clause":     "PERMISSIVE",
    "bsd-3-clause":     "PERMISSIVE",
    "isc":              "PERMISSIVE",
    "artistic-2.0":     "PERMISSIVE",

    # Copyleft (strong)
    "gpl-2.0":          "COPYLEFT_STRONG",
    "gpl-3.0":          "COPYLEFT_STRONG",
    "agpl-3.0":         "COPYLEFT_STRONG",

    # Copyleft (weak)
    "lgpl-2.0":         "COPYLEFT_WEAK",
    "lgpl-2.1":         "COPYLEFT_WEAK",
    "lgpl-3.0":         "COPYLEFT_WEAK",

    # Custom restricted (AI-specific)
    "llama2":           "CUSTOM_RESTRICTED",
    "llama3":           "CUSTOM_RESTRICTED",
    "llama3.1":         "CUSTOM_RESTRICTED",
    "llama3.2":         "CUSTOM_RESTRICTED",
    "llama3.3":         "CUSTOM_RESTRICTED",
    "gemma":            "CUSTOM_RESTRICTED",

    # Restricted use (OpenRAIL family)
    "openrail":         "RESTRICTED_USE",
    "openrail++":       "RESTRICTED_USE",
    "creativeml-openrail-m": "RESTRICTED_USE",
    "bigscience-openrail-m": "RESTRICTED_USE",
    "bigscience-bloom-rail-1.0": "RESTRICTED_USE",
    "bigcode-openrail-m": "RESTRICTED_USE",

    # Non-commercial
    "cc-by-nc-4.0":     "NON_COMMERCIAL",
    "cc-by-nc-sa-4.0":  "NON_COMMERCIAL",
    "cc-by-nc-nd-4.0":  "NON_COMMERCIAL",

    # ShareAlike (propagation risk)
    "cc-by-sa-4.0":     "SHARE_ALIKE",
    "cc-by-sa-3.0":     "SHARE_ALIKE",

    # Requires manual review
    "other":            "CUSTOM_REVIEW_REQUIRED",
}

LLAMA_MODEL_PREFIXES = ("meta-llama/", "meta-llama-")

OPENRAIL_CATEGORIES = {"RESTRICTED_USE"}

OPENRAIL_PROHIBITED_USES = [
    "surveillance or tracking of individuals without consent",
    "military weapons targeting or autonomous weapons systems",
    "generating disinformation or coordinated inauthentic behavior",
    "discriminatory profiling based on protected characteristics",
    "predicting recidivism or parole decisions",
    "generating CSAM or sexual content involving minors",
]

# ---------------------------------------------------------------------------
# Regex patterns for model references in Python code
# ---------------------------------------------------------------------------

PY_MODEL_PATTERNS = [
    # .from_pretrained("org/model") — covers all Auto* and pipeline classes
    re.compile(r'\.from_pretrained\(\s*["\']([a-zA-Z0-9_.-]+/[a-zA-Z0-9._-]+)["\']'),
    # pipeline("task", model="org/model")
    re.compile(r'pipeline\([^)]*model\s*=\s*["\']([a-zA-Z0-9_.-]+/[a-zA-Z0-9._-]+)["\']'),
    # SentenceTransformer("org/model")
    re.compile(r'SentenceTransformer\(\s*["\']([a-zA-Z0-9_.-]+/[a-zA-Z0-9._-]+)["\']'),
    # Module-level constant assignment: MODEL_ID = "org/model"
    re.compile(r'[A-Z_][A-Z0-9_]*\s*=\s*["\']([a-zA-Z0-9_.-]+/[a-zA-Z0-9._-]+)["\']'),
    # DiffusionPipeline / StableDiffusionPipeline already caught by from_pretrained
]

# Detect dynamic (variable-based) references — these cannot be resolved
PY_DYNAMIC_PATTERNS = [
    re.compile(r'\.from_pretrained\(\s*([a-zA-Z_][a-zA-Z0-9_]*)[\s,)]'),
    re.compile(r'\.from_pretrained\(\s*f["\']'),  # f-string
    re.compile(r'\.from_pretrained\(\s*["\'][^"\']*\{'),  # f-string brace
]

# Config file keys that may hold model IDs
CONFIG_MODEL_KEYS = {
    "model_name_or_path", "pretrained_model_name_or_path",
    "base_model", "model_name", "model_id",
    "MODEL_NAME", "HF_MODEL_ID", "BASE_MODEL",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ModelFinding:
    model_id: str
    source_file: str
    license_id: Optional[str] = None
    license_category: Optional[str] = None
    severity: Optional[str] = None
    violations: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    remediation: list = field(default_factory=list)
    unresolved: bool = False
    private_or_missing: bool = False


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

CACHE_FILE = Path(".cache/hf_model_cache.json")


def _load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=2))


# ---------------------------------------------------------------------------
# HF Hub license resolution
# ---------------------------------------------------------------------------

def resolve_model_license(model_id: str, cache: dict, token: Optional[str] = None) -> dict:
    """
    Returns {"license": str, "license_name": str|None, "license_link": str|None}
    Uses local cache to avoid repeated API calls.
    """
    if model_id in cache:
        return cache[model_id]

    api = HfApi(token=token)
    result = {"license": None, "license_name": None, "license_link": None}

    for attempt in range(3):
        try:
            info = api.model_info(model_id, cardData=True)

            # License from tags (most reliable)
            for tag in (info.tags or []):
                if tag.startswith("license:"):
                    result["license"] = tag[len("license:"):]
                    break

            # Enrich with cardData (always, for license_name/link on "other")
            if info.cardData:
                card = info.cardData
                if not result["license"]:
                    result["license"] = card.get("license")
                if result["license"] == "other":
                    result["license_name"] = card.get("license_name")
                    result["license_link"] = card.get("license_link")

            break

        except RepositoryNotFoundError:
            result["error"] = "private_or_not_found"
            break
        except HfHubHTTPError as e:
            if e.response.status_code == 429:
                wait = 2 ** attempt
                logger.warning(f"Rate limited for {model_id}, retrying in {wait}s")
                time.sleep(wait)
            else:
                result["error"] = str(e)
                break
        except Exception as e:
            result["error"] = str(e)
            break

    cache[model_id] = result
    return result


# ---------------------------------------------------------------------------
# Llama-specific checks
# ---------------------------------------------------------------------------

def check_llama_violations(model_id: str, repo_root: Path) -> tuple[list, list]:
    """
    Returns (violations, warnings) specific to Llama license obligations.
    """
    violations = []
    warnings = []
    model_lower = model_id.lower()

    # Attribution check — "Built with Meta Llama" must appear in README
    readme_files = list(repo_root.glob("README*")) + list(repo_root.glob("readme*"))
    attribution_found = False
    for readme in readme_files:
        try:
            if "built with meta llama" in readme.read_text(errors="ignore").lower():
                attribution_found = True
                break
        except Exception:
            pass

    if not attribution_found:
        violations.append({
            "type": "MISSING_ATTRIBUTION",
            "severity": "HIGH",
            "detail": f'"{model_id}" requires "Built with Meta Llama" attribution in README (Llama license §2.3)',
            "remediation": 'Add "Built with Meta Llama 3" to your README.md',
        })

    # Anti-distillation check — Llama 3 (not 3.1+) prohibits using outputs to train competing models
    if "llama-3" in model_lower and "llama-3.1" not in model_lower and "llama-3.2" not in model_lower and "llama-3.3" not in model_lower:
        distill_files = list(repo_root.rglob("distill*.py")) + list(repo_root.rglob("*distill*.py"))
        train_files = list(repo_root.rglob("train*.py")) + list(repo_root.rglob("*finetune*.py"))
        if distill_files or train_files:
            violations.append({
                "type": "ANTI_DISTILLATION",
                "severity": "HIGH",
                "detail": f'Llama 3 license §1.b.v prohibits using model outputs to train competing LLMs. '
                          f'Detected training/distillation scripts: '
                          f'{[f.name for f in (distill_files + train_files)[:3]]}',
                "remediation": "Use Llama 3.1+ (anti-distillation clause was relaxed) or remove training scripts that use Llama outputs.",
            })

    # 700M MAU threshold — always an INFO warning
    warnings.append({
        "type": "MAU_THRESHOLD",
        "severity": "INFO",
        "detail": f'"{model_id}": Llama license requires a separate Meta license if your product exceeds 700M monthly active users.',
        "remediation": "Contact Meta for a separate license if MAU exceeds 700M.",
    })

    return violations, warnings


# ---------------------------------------------------------------------------
# OpenRAIL flagging
# ---------------------------------------------------------------------------

def flag_openrail(model_id: str, license_id: str) -> list:
    warnings = []
    for use_case in OPENRAIL_PROHIBITED_USES:
        warnings.append({
            "type": "OPENRAIL_USE_RESTRICTION",
            "severity": "MEDIUM",
            "detail": f'"{model_id}" uses {license_id} which prohibits: {use_case}. '
                      f'These restrictions propagate to all derivative works.',
            "remediation": "Review your application against all OpenRAIL prohibited use cases. Consult legal if any apply.",
        })
    return warnings


# ---------------------------------------------------------------------------
# Python file scanner
# ---------------------------------------------------------------------------

def scan_python_files(repo_root: Path) -> tuple[dict, list]:
    """
    Returns:
      - resolved: {model_id: [source_files]} for string-literal references
      - unresolved: [{"file": str, "line": int, "snippet": str}] for dynamic refs
    """
    resolved = {}
    unresolved = []

    for py_file in repo_root.rglob("*.py"):
        # Skip .venv and test fixtures
        if ".venv" in py_file.parts or "__pycache__" in py_file.parts:
            continue
        try:
            source = py_file.read_text(errors="ignore")
        except Exception:
            continue

        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            # Check for dynamic references first
            for dyn_pat in PY_DYNAMIC_PATTERNS:
                if dyn_pat.search(line):
                    unresolved.append({
                        "file": str(py_file.relative_to(repo_root)),
                        "line": i,
                        "snippet": line.strip(),
                    })
                    break
            else:
                # Static string literal references
                for pat in PY_MODEL_PATTERNS:
                    for match in pat.finditer(line):
                        model_id = match.group(1)
                        resolved.setdefault(model_id, [])
                        src = str(py_file.relative_to(repo_root))
                        if src not in resolved[model_id]:
                            resolved[model_id].append(src)

    return resolved, unresolved


# ---------------------------------------------------------------------------
# Config file scanner
# ---------------------------------------------------------------------------

def scan_config_files(repo_root: Path) -> dict:
    """
    Scans YAML, JSON, .env, Dockerfiles for model ID references.
    Returns {model_id: [source_files]}.
    """
    import yaml

    found = {}

    def _add(model_id, source):
        found.setdefault(model_id, [])
        if source not in found[model_id]:
            found[model_id].append(source)

    hf_id_re = re.compile(r'["\']?([a-zA-Z0-9_.-]+/[a-zA-Z0-9._-]+)["\']?')

    # YAML files
    for yaml_file in list(repo_root.rglob("*.yml")) + list(repo_root.rglob("*.yaml")):
        if ".venv" in yaml_file.parts or ".git" in yaml_file.parts:
            continue
        try:
            data = yaml.safe_load(yaml_file.read_text(errors="ignore"))
            if not isinstance(data, dict):
                continue
            _scan_dict_for_model_keys(data, str(yaml_file.relative_to(repo_root)), _add)
        except Exception:
            pass

    # JSON files
    for json_file in repo_root.rglob("*.json"):
        if ".venv" in json_file.parts or ".git" in json_file.parts:
            continue
        try:
            data = json.loads(json_file.read_text(errors="ignore"))
            if isinstance(data, dict):
                _scan_dict_for_model_keys(data, str(json_file.relative_to(repo_root)), _add)
        except Exception:
            pass

    # .env files
    for env_file in repo_root.rglob(".env*"):
        if ".venv" in env_file.parts:
            continue
        try:
            for line in env_file.read_text(errors="ignore").splitlines():
                key, _, value = line.partition("=")
                if key.strip() in CONFIG_MODEL_KEYS and "/" in value:
                    m = hf_id_re.search(value)
                    if m:
                        _add(m.group(1), str(env_file.relative_to(repo_root)))
        except Exception:
            pass

    return found


def _scan_dict_for_model_keys(data: dict, source: str, add_fn) -> None:
    hf_id_re = re.compile(r'^[a-zA-Z0-9_.-]+/[a-zA-Z0-9._-]+$')
    for key, value in data.items():
        if key in CONFIG_MODEL_KEYS and isinstance(value, str):
            if hf_id_re.match(value.strip()):
                add_fn(value.strip(), source)
        elif isinstance(value, dict):
            _scan_dict_for_model_keys(value, source, add_fn)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan(repo_root: str | Path, hf_token: Optional[str] = None) -> dict:
    """
    Full model license scan of a repository.

    Returns:
    {
      "findings": [ModelFinding, ...],
      "unresolved": [...],
      "summary": {"total": int, "critical": int, "high": int, "medium": int, "warning": int, "info": int}
    }
    """
    repo_root = Path(repo_root).resolve()
    cache = _load_cache()
    findings = []

    # --- Collect all model references ---
    py_models, unresolved = scan_python_files(repo_root)
    cfg_models = scan_config_files(repo_root)

    # Merge sources
    all_models: dict[str, list] = {}
    for model_id, sources in {**py_models, **cfg_models}.items():
        all_models.setdefault(model_id, [])
        for s in sources:
            if s not in all_models[model_id]:
                all_models[model_id].append(s)

    # --- Resolve each model ---
    for model_id, source_files in all_models.items():
        finding = ModelFinding(
            model_id=model_id,
            source_file=", ".join(source_files),
        )

        license_data = resolve_model_license(model_id, cache, token=hf_token)

        if license_data.get("error") == "private_or_not_found":
            finding.private_or_missing = True
            finding.severity = "WARNING"
            finding.warnings.append({
                "type": "PRIVATE_OR_MISSING",
                "severity": "WARNING",
                "detail": f'"{model_id}" could not be found on Hugging Face Hub (private or deleted). License unknown.',
                "remediation": "Verify the model ID is correct and accessible, or document the license manually.",
            })
            findings.append(finding)
            continue

        license_id = license_data.get("license")
        finding.license_id = license_id

        if not license_id:
            finding.severity = "WARNING"
            finding.warnings.append({
                "type": "MISSING_LICENSE",
                "severity": "WARNING",
                "detail": f'"{model_id}" has no license metadata on Hugging Face Hub.',
                "remediation": "Check the model card manually and document the license. Treat as All Rights Reserved if unclear.",
            })
            findings.append(finding)
            continue

        category = LICENSE_TAXONOMY.get(license_id.lower(), "UNKNOWN_RISK")
        finding.license_category = category

        # --- Apply rules by category ---
        if category == "COPYLEFT_STRONG":
            finding.severity = "CRITICAL"
            finding.violations.append({
                "type": "COPYLEFT_STRONG",
                "severity": "CRITICAL",
                "detail": f'"{model_id}" uses {license_id}. AGPL/GPL requires full source disclosure for network/SaaS use.',
                "remediation": "Replace with a permissively licensed alternative or purchase a commercial license.",
            })

        elif category == "CUSTOM_RESTRICTED":
            # Llama family
            if any(model_id.lower().startswith(p) for p in LLAMA_MODEL_PREFIXES):
                llama_violations, llama_warnings = check_llama_violations(model_id, repo_root)
                finding.violations.extend(llama_violations)
                finding.warnings.extend(llama_warnings)
                finding.severity = "HIGH" if llama_violations else "MEDIUM"
            else:
                finding.severity = "MEDIUM"
                finding.warnings.append({
                    "type": "CUSTOM_LICENSE",
                    "severity": "MEDIUM",
                    "detail": f'"{model_id}" uses a custom restricted license ({license_id}). Manual review required.',
                    "remediation": "Review the full license text and consult legal before commercial use.",
                })

        elif category == "RESTRICTED_USE":
            openrail_warnings = flag_openrail(model_id, license_id)
            finding.warnings.extend(openrail_warnings)
            finding.severity = "MEDIUM"

        elif category == "NON_COMMERCIAL":
            finding.severity = "HIGH"
            finding.violations.append({
                "type": "NON_COMMERCIAL",
                "severity": "HIGH",
                "detail": f'"{model_id}" uses {license_id} which prohibits commercial use.',
                "remediation": "Replace with a commercially licensed model or obtain a separate commercial license.",
            })

        elif category == "SHARE_ALIKE":
            finding.severity = "MEDIUM"
            finding.warnings.append({
                "type": "SHARE_ALIKE",
                "severity": "MEDIUM",
                "detail": f'"{model_id}" uses {license_id}. ShareAlike may require derivative works to use the same license.',
                "remediation": "Consult legal on whether your use constitutes a derivative work requiring ShareAlike compliance.",
            })

        elif category == "UNKNOWN_RISK":
            finding.severity = "WARNING"
            finding.warnings.append({
                "type": "UNKNOWN_LICENSE",
                "severity": "WARNING",
                "detail": f'"{model_id}" has unrecognized license "{license_id}". Cannot assess compliance automatically.',
                "remediation": "Review the license text manually and document your compliance assessment.",
            })

        elif category == "CUSTOM_REVIEW_REQUIRED":
            name = license_data.get("license_name", "unknown")
            link = license_data.get("license_link", "")
            finding.severity = "MEDIUM"
            finding.warnings.append({
                "type": "CUSTOM_LICENSE",
                "severity": "MEDIUM",
                "detail": f'"{model_id}" uses a custom license: "{name}". {f"See: {link}" if link else ""}',
                "remediation": "Review the full license text and consult legal before commercial use.",
            })

        else:
            # PERMISSIVE, COPYLEFT_WEAK
            finding.severity = "INFO"

        findings.append(finding)

    _save_cache(cache)

    # --- Summary ---
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 3, "INFO": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity or "INFO", 4))

    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "warning": 0, "info": 0}
    for f in findings:
        s = (f.severity or "INFO").lower()
        if s in summary:
            summary[s] += 1

    return {
        "findings": findings,
        "unresolved": unresolved,
        "summary": summary,
    }


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    token = os.environ.get("HF_TOKEN")
    results = scan(target, hf_token=token)

    print(f"\n=== Model Scanner Results ===")
    print(f"Total models found: {results['summary']['total']}")
    print(f"CRITICAL: {results['summary']['critical']} | HIGH: {results['summary']['high']} | "
          f"MEDIUM: {results['summary']['medium']} | WARNING: {results['summary']['warning']} | "
          f"INFO: {results['summary']['info']}")

    for f in results["findings"]:
        print(f"\n[{f.severity}] {f.model_id} ({f.license_id or 'no license'})")
        print(f"  Found in: {f.source_file}")
        for v in f.violations:
            print(f"  ❌ {v['type']}: {v['detail']}")
        for w in f.warnings:
            print(f"  ⚠️  {w['type']}: {w['detail']}")

    if results["unresolved"]:
        print(f"\n=== Unresolved Dynamic References ({len(results['unresolved'])}) ===")
        for u in results["unresolved"]:
            print(f"  {u['file']}:{u['line']} — {u['snippet']}")
