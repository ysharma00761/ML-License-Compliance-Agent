"""
Training Dataset License Scanner

Scans a repository for Hugging Face dataset references (load_dataset() calls
and config file keys), resolves their licenses via the HF Hub API, and flags
datasets whose terms conflict with commercial or ShareAlike use.
"""

import json
import logging
import re
import time
from pathlib import Path
from typing import Optional

import yaml
from huggingface_hub import HfApi
from huggingface_hub.utils import RepositoryNotFoundError, HfHubHTTPError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for dataset extraction
# ---------------------------------------------------------------------------

# Static patterns — extract literal dataset IDs from load_dataset() calls
PY_DATASET_PATTERNS = [
    re.compile(r'''load_dataset\(\s*["']([a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9._-]+)?)["']'''),
]

# Module-level constant assignments: DATASET_ID = "org/name"
PY_CONSTANT_PATTERN = re.compile(
    r'''^[A-Z_][A-Z0-9_]*\s*=\s*["']([a-zA-Z0-9_.-]+/[a-zA-Z0-9._-]+)["']'''
)

# Dynamic patterns — flag unresolvable references
PY_DYNAMIC_PATTERNS = [
    re.compile(r'''load_dataset\(\s*([a-zA-Z_][a-zA-Z0-9_]*)[\s,)]'''),
    re.compile(r'''load_dataset\(\s*f["']'''),
    re.compile(r'''load_dataset\(\s*["'].*\{'''),
]

# Config file keys that may hold dataset IDs
CONFIG_DATASET_KEYS = {
    "dataset_name", "dataset_path", "train_dataset", "eval_dataset",
    "dataset_id", "DATASET_NAME", "HF_DATASET_ID",
}

# ---------------------------------------------------------------------------
# Well-known dataset registry
# ---------------------------------------------------------------------------

WELL_KNOWN_DATASETS = {
    "common_crawl": {
        "license": "CUSTOM_TOU",
        "commercial_eligible": False,
        "note": "Scraped pages retain original copyright; no unified license.",
    },
    "laion/laion5B": {
        "license": "CC-BY-4.0",
        "commercial_eligible": True,
        "note": "Metadata only; images retain original copyright.",
    },
    "EleutherAI/pile": {
        "license": "MIT",
        "commercial_eligible": True,
        "note": "Assembly license; sub-datasets have individual licenses.",
    },
    "wikipedia": {
        "license": "CC-BY-SA-3.0",
        "commercial_eligible": True,
        "note": "ShareAlike: derivative works must use same license.",
    },
    "imagenet-1k": {
        "license": "CUSTOM_RESEARCH_ONLY",
        "commercial_eligible": False,
        "note": "Non-commercial; commercial license must be obtained separately.",
    },
    "ms-coco": {
        "license": "CC-BY-4.0",
        "commercial_eligible": True,
        "note": "Annotations only; images lack attribution.",
    },
    "bigcode/the-stack": {
        "license": "PER_FILE",
        "commercial_eligible": None,
        "note": "Individual files retain original licenses including GPL/AGPL.",
    },
    "NVlabs/ffhq-dataset": {
        "license": "CC-BY-NC-SA-4.0",
        "commercial_eligible": False,
        "note": "Non-commercial and ShareAlike restrictions.",
    },
    "lmsys/chatbot_arena_conversations": {
        "license": "CC-BY-NC-4.0",
        "commercial_eligible": False,
        "note": "Non-commercial only.",
    },
}

# License categories
NON_COMMERCIAL_LICENSES = {
    "cc-by-nc-4.0", "cc-by-nc-sa-4.0", "cc-by-nc-nd-4.0",
    "cc-by-nc-3.0", "cc-by-nc-sa-3.0", "cc-by-nc-nd-3.0",
}
SHAREALIKE_LICENSES = {"cc-by-sa-4.0", "cc-by-sa-3.0"}
RESEARCH_ONLY_LICENSES = {"CUSTOM_RESEARCH_ONLY"}

# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

CACHE_FILE = Path(".cache/hf_dataset_cache.json")


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
# Code scanning
# ---------------------------------------------------------------------------

_SKIP_DIRS = {".venv", "__pycache__", ".git", "node_modules", ".tox"}


def scan_python_files(repo_root: Path) -> tuple[dict, list]:
    """
    Scan all .py files for load_dataset() calls.

    Returns:
        resolved: {dataset_id: [source_files]}
        unresolved: [{"file": str, "line": int, "snippet": str}]
    """
    resolved: dict[str, list[str]] = {}
    unresolved: list[dict] = []

    for py_file in repo_root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in py_file.parts):
            continue

        try:
            lines = py_file.read_text(errors="ignore").splitlines()
        except Exception:
            continue

        rel_path = str(py_file.relative_to(repo_root))

        for line_no, line in enumerate(lines, 1):
            # Resolve module-level constant assignments: DATASET_ID = "org/name"
            m = PY_CONSTANT_PATTERN.match(line.strip())
            if m:
                dataset_id = m.group(1)
                if rel_path not in resolved.get(dataset_id, []):
                    resolved.setdefault(dataset_id, []).append(rel_path)

            if "load_dataset" not in line:
                continue

            # Check dynamic patterns first
            is_dynamic = False
            for pat in PY_DYNAMIC_PATTERNS:
                m = pat.search(line)
                if m:
                    # Make sure it's not also a static match
                    static_match = any(sp.search(line) for sp in PY_DATASET_PATTERNS)
                    if not static_match:
                        unresolved.append({
                            "file": rel_path,
                            "line": line_no,
                            "snippet": line.strip()[:120],
                        })
                        is_dynamic = True
                        break

            if is_dynamic:
                continue

            # Check static patterns
            for pat in PY_DATASET_PATTERNS:
                m = pat.search(line)
                if m:
                    dataset_id = m.group(1)
                    if rel_path not in resolved.get(dataset_id, []):
                        resolved.setdefault(dataset_id, []).append(rel_path)

    return resolved, unresolved


def scan_config_files(repo_root: Path) -> dict[str, list[str]]:
    """
    Scan YAML, JSON, and .env files for dataset references.

    Returns: {dataset_id: [source_files]}
    """
    resolved: dict[str, list[str]] = {}

    def _check_value(val: str, source: str):
        if val and isinstance(val, str) and len(val) < 200:
            # Looks like a dataset ID (org/name or just name)
            if re.match(r"^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9._-]+)?$", val.strip()):
                did = val.strip()
                if source not in resolved.get(did, []):
                    resolved.setdefault(did, []).append(source)

    def _scan_dict(data: dict, source: str):
        if not isinstance(data, dict):
            return
        for key, val in data.items():
            if key in CONFIG_DATASET_KEYS and isinstance(val, str):
                _check_value(val, source)
            elif isinstance(val, dict):
                _scan_dict(val, source)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        _scan_dict(item, source)

    # YAML files
    for yf in repo_root.rglob("*.y*ml"):
        if any(part in _SKIP_DIRS for part in yf.parts):
            continue
        try:
            data = yaml.safe_load(yf.read_text(errors="ignore"))
            if isinstance(data, dict):
                _scan_dict(data, str(yf.relative_to(repo_root)))
        except Exception:
            continue

    # JSON files
    for jf in repo_root.rglob("*.json"):
        if any(part in _SKIP_DIRS for part in jf.parts):
            continue
        try:
            data = json.loads(jf.read_text(errors="ignore"))
            if isinstance(data, dict):
                _scan_dict(data, str(jf.relative_to(repo_root)))
        except Exception:
            continue

    # .env files
    for ef in repo_root.rglob(".env*"):
        if any(part in _SKIP_DIRS for part in ef.parts):
            continue
        try:
            rel = str(ef.relative_to(repo_root))
            for line in ef.read_text(errors="ignore").splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, _, val = line.partition("=")
                    if key.strip() in CONFIG_DATASET_KEYS:
                        _check_value(val.strip().strip("'\""), rel)
        except Exception:
            continue

    return resolved


# ---------------------------------------------------------------------------
# License resolution
# ---------------------------------------------------------------------------

def _lookup_well_known(dataset_id: str) -> Optional[dict]:
    """Check the well-known dataset registry. Supports substring matching."""
    # Exact match first
    if dataset_id in WELL_KNOWN_DATASETS:
        return WELL_KNOWN_DATASETS[dataset_id]
    # Substring match
    did_lower = dataset_id.lower()
    for known_id, info in WELL_KNOWN_DATASETS.items():
        if known_id.lower() in did_lower or did_lower in known_id.lower():
            return info
    return None


def resolve_dataset_license(dataset_id: str, cache: dict, token: Optional[str] = None) -> dict:
    """
    Resolve dataset license via well-known registry or HF Hub API.

    Returns: {"license": str|None, "license_name": str|None, "error": str|None}
    """
    if dataset_id in cache:
        return cache[dataset_id]

    result = {"license": None, "license_name": None, "error": None}

    # Check well-known registry first
    well_known = _lookup_well_known(dataset_id)
    if well_known:
        result["license"] = well_known["license"]
        result["license_name"] = well_known.get("note")
        cache[dataset_id] = result
        return result

    # Query HF Hub API
    api = HfApi(token=token)
    for attempt in range(3):
        try:
            info = api.dataset_info(dataset_id)

            # Extract license from tags
            for tag in (info.tags or []):
                if tag.startswith("license:"):
                    result["license"] = tag[len("license:"):]
                    break

            # Fallback to card data
            if not result["license"] and hasattr(info, "cardData") and info.cardData:
                result["license"] = info.cardData.get("license")
                result["license_name"] = info.cardData.get("license_name")

            cache[dataset_id] = result
            return result

        except RepositoryNotFoundError:
            result["error"] = "not_found"
            cache[dataset_id] = result
            return result

        except HfHubHTTPError as e:
            if "429" in str(e) and attempt < 2:
                time.sleep(2 ** attempt)
                continue
            result["error"] = str(e)
            cache[dataset_id] = result
            return result

        except Exception as e:
            result["error"] = str(e)
            cache[dataset_id] = result
            return result

    return result


# ---------------------------------------------------------------------------
# Violation classification
# ---------------------------------------------------------------------------

def _classify_dataset(dataset_id: str, license_id: Optional[str], well_known: Optional[dict]) -> tuple[list, list, bool]:
    """
    Classify a dataset's license and return (violations, warnings, commercial_eligible).
    """
    violations: list[dict] = []
    warnings: list[dict] = []
    commercial_eligible = True

    if not license_id:
        commercial_eligible = False  # Unknown = assume not safe
        warnings.append({
            "type": "MISSING_LICENSE",
            "severity": "WARNING",
            "detail": f"Dataset '{dataset_id}' has no license metadata. Manual review required.",
            "remediation": "Check the dataset page for a LICENSE file and verify terms before use.",
        })
        return violations, warnings, commercial_eligible

    lic_lower = license_id.lower()

    # Non-commercial licenses
    if lic_lower in NON_COMMERCIAL_LICENSES:
        commercial_eligible = False
        violations.append({
            "type": "NON_COMMERCIAL",
            "severity": "HIGH",
            "detail": (
                f"Dataset '{dataset_id}' is licensed under {license_id} (non-commercial). "
                "Commercial training or deployment is a clear violation."
            ),
            "remediation": "Replace with a permissively licensed alternative dataset (CC-BY-4.0 or Apache-2.0).",
        })

    # ShareAlike licenses
    elif lic_lower in SHAREALIKE_LICENSES:
        warnings.append({
            "type": "SHAREALIKE",
            "severity": "MEDIUM",
            "detail": (
                f"Dataset '{dataset_id}' is licensed under {license_id} (ShareAlike). "
                "Derivative works may need to use the same license — legal review recommended."
            ),
            "remediation": "Consult legal counsel on ShareAlike propagation, or replace with CC-BY-4.0 dataset.",
        })

    # Research-only
    elif license_id in RESEARCH_ONLY_LICENSES:
        commercial_eligible = False
        violations.append({
            "type": "RESEARCH_ONLY",
            "severity": "HIGH",
            "detail": (
                f"Dataset '{dataset_id}' is restricted to research/non-commercial use. "
                "A separate commercial license must be obtained."
            ),
            "remediation": "Obtain a commercial license or replace with a commercially licensed dataset.",
        })

    # Custom TOU (e.g., Common Crawl)
    elif license_id == "CUSTOM_TOU":
        commercial_eligible = False
        warnings.append({
            "type": "CUSTOM_TOU",
            "severity": "WARNING",
            "detail": f"Dataset '{dataset_id}' has custom terms of use. Manual review required.",
            "remediation": "Review the dataset's terms of use page for commercial eligibility.",
        })

    # PER_FILE (e.g., The Stack)
    elif license_id == "PER_FILE":
        warnings.append({
            "type": "PER_FILE_LICENSE",
            "severity": "WARNING",
            "detail": (
                f"Dataset '{dataset_id}' contains files under individual licenses "
                "including potentially GPL/AGPL. Per-file review needed."
            ),
            "remediation": "Filter the dataset to include only permissively licensed files.",
        })

    # Add well-known dataset notes as informational
    if well_known and well_known.get("note"):
        if well_known.get("commercial_eligible") is not None:
            commercial_eligible = well_known["commercial_eligible"]

    return violations, warnings, commercial_eligible


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def scan(repo_root: str | Path, hf_token: Optional[str] = None) -> dict:
    """
    Scan a repository for training dataset license compliance issues.

    Returns:
        {
            "findings": [
                {
                    "dataset_id": str,
                    "license_id": str | None,
                    "source_file": str,
                    "commercial_eligible": bool,
                    "violations": [...],
                    "warnings": [...]
                }
            ]
        }
    """
    repo_root = Path(repo_root).resolve()
    cache = _load_cache()

    # 1. Scan for dataset references
    py_resolved, py_unresolved = scan_python_files(repo_root)
    config_resolved = scan_config_files(repo_root)

    # Merge results
    all_datasets: dict[str, list[str]] = {}
    for did, files in py_resolved.items():
        all_datasets.setdefault(did, []).extend(files)
    for did, files in config_resolved.items():
        for f in files:
            if f not in all_datasets.get(did, []):
                all_datasets.setdefault(did, []).append(f)

    # 2. Resolve licenses and classify
    findings: list[dict] = []

    for dataset_id, source_files in all_datasets.items():
        # Check well-known registry
        well_known = _lookup_well_known(dataset_id)

        # Resolve license
        license_info = resolve_dataset_license(dataset_id, cache, token=hf_token)
        license_id = license_info.get("license")

        # If well-known override has a license, prefer it
        if well_known and well_known.get("license"):
            license_id = well_known["license"]

        # Classify
        violations, warnings, commercial_eligible = _classify_dataset(
            dataset_id, license_id, well_known
        )

        # Handle unresolved API lookups
        if license_info.get("error") == "not_found":
            warnings.append({
                "type": "DATASET_NOT_FOUND",
                "severity": "WARNING",
                "detail": f"Dataset '{dataset_id}' not found on Hugging Face Hub (may be private or removed).",
                "remediation": "Verify the dataset ID and check if it requires authentication.",
            })

        findings.append({
            "dataset_id": dataset_id,
            "license_id": license_id,
            "source_file": source_files[0] if source_files else None,
            "commercial_eligible": commercial_eligible,
            "violations": violations,
            "warnings": warnings,
        })

    # 3. Add unresolved dynamic references
    for unres in py_unresolved:
        findings.append({
            "dataset_id": f"UNRESOLVED:{unres['snippet'][:60]}",
            "license_id": None,
            "source_file": unres["file"],
            "commercial_eligible": False,
            "violations": [],
            "warnings": [{
                "type": "UNRESOLVED_REFERENCE",
                "severity": "WARNING",
                "detail": (
                    f"Dynamic dataset reference at {unres['file']}:{unres['line']} — "
                    f"`{unres['snippet'][:80]}`. Cannot resolve automatically."
                ),
                "remediation": "Replace with a static string literal or add manual review.",
            }],
        })

    _save_cache(cache)

    return {"findings": findings}
