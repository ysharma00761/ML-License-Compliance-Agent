"""
Python Package License Scanner

Scans a repository for Python dependency files (requirements.txt, pyproject.toml,
Pipfile), resolves the transitive dependency tree, looks up licenses via deps.dev
and PyPI APIs, and flags compliance violations.
"""

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# License normalization — free-text → SPDX
# ---------------------------------------------------------------------------

LICENSE_NORMALIZE_MAP = {
    "mit license": "MIT",
    "mit": "MIT",
    "bsd license": "BSD-3-Clause",
    "bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "apache license 2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "isc license": "ISC",
    "isc": "ISC",
    "gnu general public license v2 (gplv2)": "GPL-2.0",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gplv2": "GPL-2.0",
    "gplv2+": "GPL-2.0-or-later",
    "gpl-2.0": "GPL-2.0",
    "gpl-2.0-only": "GPL-2.0",
    "gpl-2.0-or-later": "GPL-2.0-or-later",
    "gnu general public license v3 (gplv3)": "GPL-3.0",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gplv3": "GPL-3.0",
    "gplv3+": "GPL-3.0-or-later",
    "gpl-3.0": "GPL-3.0",
    "gpl-3.0-only": "GPL-3.0",
    "gpl-3.0-or-later": "GPL-3.0-or-later",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.1",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl-3.0": "LGPL-3.0",
    "lgplv3": "LGPL-3.0",
    "gnu affero general public license v3": "AGPL-3.0",
    "agpl-3.0": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    "mozilla public license 2.0": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "artistic license": "Artistic-2.0",
    "artistic-2.0": "Artistic-2.0",
    "public domain": "Unlicense",
    "unlicense": "Unlicense",
    "cc-by-4.0": "CC-BY-4.0",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    "historical permission notice and disclaimer": "HPND",
}

# ---------------------------------------------------------------------------
# Known problematic packages — hardcoded overrides
# ---------------------------------------------------------------------------

KNOWN_PROBLEMATIC_PACKAGES = {
    "python-slugify": {
        "transitive_risk": "Unidecode",
        "transitive_license": "GPL-2.0-or-later",
        "finding": {
            "type": "TRANSITIVE_GPL",
            "severity": "CRITICAL",
            "detail": (
                "python-slugify transitively depends on Unidecode (GPLv2+). "
                "GPL contaminates your project through the dependency chain."
            ),
            "remediation": (
                "Replace with text-unidecode: `pip install python-slugify[unidecode]` "
                "pinned to text-unidecode (Artistic License), or install text-unidecode directly."
            ),
        },
    },
    "ultralytics": {
        "license_override": "AGPL-3.0",
        "finding": {
            "type": "AGPL_SAAS",
            "severity": "CRITICAL",
            "detail": (
                "ultralytics (YOLOv8) is licensed under AGPL-3.0. "
                "SaaS/network deployment requires full source disclosure."
            ),
            "remediation": (
                "Purchase Ultralytics Enterprise License at ultralytics.com/license, "
                "or replace with RT-DETR (Apache-2.0)."
            ),
        },
    },
    "pyqt5": {
        "license_override": "GPL-3.0",
        "finding": {
            "type": "COPYLEFT_STRONG",
            "severity": "CRITICAL",
            "detail": "PyQt5 is licensed under GPL-3.0. Distribution triggers copyleft obligations.",
            "remediation": "Replace with PySide2 (LGPL-2.1) — same Qt5 API, commercially safe.",
        },
    },
    "pyqt6": {
        "license_override": "GPL-3.0",
        "finding": {
            "type": "COPYLEFT_STRONG",
            "severity": "CRITICAL",
            "detail": "PyQt6 is licensed under GPL-3.0. Distribution triggers copyleft obligations.",
            "remediation": "Replace with PySide6 (LGPL-2.1) — same Qt6 API, commercially safe.",
        },
    },
    "torch": {
        "bundled_warning": {
            "type": "BUNDLED_BINARY",
            "severity": "WARNING",
            "detail": "torch GPU wheels bundle NVIDIA CUDA libraries under NVIDIA's proprietary EULA.",
            "remediation": "Review NVIDIA CUDA EULA for redistribution requirements.",
        },
    },
    "opencv-python": {
        "bundled_warning": {
            "type": "BUNDLED_BINARY",
            "severity": "WARNING",
            "detail": "opencv-python (non-headless) bundles FFmpeg (LGPLv2.1) and Qt5 (LGPLv3).",
            "remediation": "Use opencv-python-headless to avoid bundled FFmpeg/Qt5 dependencies.",
        },
    },
    "bitsandbytes": {
        "bundled_warning": {
            "type": "MULTI_LICENSE",
            "severity": "WARNING",
            "detail": "bitsandbytes declares MIT but contains multi-license portions.",
            "remediation": "Review individual source files for license terms.",
        },
    },
    "torchaudio": {
        "bundled_warning": {
            "type": "CONDITIONAL_GPL",
            "severity": "WARNING",
            "detail": "torchaudio with FFmpeg --enable-gpl makes runtime license GPL.",
            "remediation": "Ensure FFmpeg is built without --enable-gpl flag.",
        },
    },
}

SAAS_INDICATOR_PACKAGES = {"fastapi", "flask", "uvicorn", "gunicorn", "starlette"}

# Licenses that trigger copyleft findings
GPL_FAMILY = {"GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"}
AGPL_FAMILY = {"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"}
LGPL_FAMILY = {"LGPL-2.0", "LGPL-2.1", "LGPL-3.0"}

# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

CACHE_FILE = Path(".cache/package_license_cache.json")


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
# Dependency file parsers
# ---------------------------------------------------------------------------

_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9][\w.-]*)"          # package name
    r"(?:\[[\w,.-]+\])?"               # optional extras [extra1,extra2]
    r"\s*((?:==|>=|<=|~=|!=|>|<).*)?$" # optional version spec
)


def parse_requirements_txt(file_path: Path) -> dict[str, str]:
    """Parse a requirements.txt file. Returns {package_name: version_spec}."""
    deps: dict[str, str] = {}
    if not file_path.exists():
        return deps

    for raw_line in file_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            name = m.group(1).lower()
            version = (m.group(2) or "").strip()
            deps[name] = version

    return deps


def parse_pyproject_toml(file_path: Path) -> dict[str, str]:
    """Parse pyproject.toml for dependencies. Returns {package_name: version_spec}."""
    deps: dict[str, str] = {}
    if not file_path.exists():
        return deps

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            logger.warning("tomllib/tomli not available, skipping pyproject.toml")
            return deps

    try:
        data = tomllib.loads(file_path.read_text())
    except Exception as e:
        logger.warning(f"Failed to parse {file_path}: {e}")
        return deps

    # [project.dependencies]
    for dep_str in data.get("project", {}).get("dependencies", []):
        m = _REQ_LINE_RE.match(dep_str.strip())
        if m:
            deps[m.group(1).lower()] = (m.group(2) or "").strip()

    # [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, str):
            deps[name.lower()] = spec
        elif isinstance(spec, dict):
            deps[name.lower()] = spec.get("version", "")

    return deps


def parse_pipfile(file_path: Path) -> dict[str, str]:
    """Parse Pipfile for dependencies. Returns {package_name: version_spec}."""
    deps: dict[str, str] = {}
    if not file_path.exists():
        return deps

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            logger.warning("tomllib/tomli not available, skipping Pipfile")
            return deps

    try:
        data = tomllib.loads(file_path.read_text())
    except Exception as e:
        logger.warning(f"Failed to parse {file_path}: {e}")
        return deps

    for section in ("packages", "dev-packages"):
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, str):
                deps[name.lower()] = spec if spec != "*" else ""
            elif isinstance(spec, dict):
                deps[name.lower()] = spec.get("version", "")

    return deps


def collect_all_dependencies(repo_root: Path) -> dict[str, str]:
    """Find and merge all dependency files in the repo. Returns {package: version_spec}."""
    all_deps: dict[str, str] = {}

    # requirements*.txt files in repo root
    for req_file in sorted(repo_root.glob("requirements*.txt")):
        all_deps.update(parse_requirements_txt(req_file))

    # pyproject.toml
    pyproject = repo_root / "pyproject.toml"
    if pyproject.exists():
        all_deps.update(parse_pyproject_toml(pyproject))

    # Pipfile
    pipfile = repo_root / "Pipfile"
    if pipfile.exists():
        all_deps.update(parse_pipfile(pipfile))

    return all_deps


# ---------------------------------------------------------------------------
# Transitive dependency resolution
# ---------------------------------------------------------------------------

def resolve_transitive_deps() -> dict[str, list[str]]:
    """
    Use pipdeptree to build the transitive dependency graph.
    Returns {package: [transitive_dep_names]}.
    Falls back to empty dict if pipdeptree is unavailable.
    """
    try:
        result = subprocess.run(
            ["pipdeptree", "--json-tree"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            logger.warning("pipdeptree returned non-zero exit code")
            return {}

        tree = json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        logger.warning(f"pipdeptree not available or failed: {e}")
        return {}

    graph: dict[str, list[str]] = {}

    def _collect_deps(node: dict, top_name: str):
        for dep in node.get("dependencies", []):
            dep_name = dep.get("package_name", dep.get("key", "")).lower()
            if dep_name and dep_name not in graph.get(top_name, []):
                graph.setdefault(top_name, []).append(dep_name)
                _collect_deps(dep, top_name)

    for top_pkg in tree:
        name = top_pkg.get("package_name", top_pkg.get("key", "")).lower()
        if name:
            graph.setdefault(name, [])
            _collect_deps(top_pkg, name)

    return graph


# ---------------------------------------------------------------------------
# License resolution via APIs
# ---------------------------------------------------------------------------

def resolve_license_deps_dev(package_name: str, version: str, cache: dict) -> Optional[dict]:
    """Query deps.dev API for package license. Returns {"license": str, "source": "deps.dev"} or None."""
    cache_key = f"deps.dev:{package_name}:{version}"
    if cache_key in cache:
        return cache[cache_key]

    clean_version = version.lstrip("=<>~! ")
    if not clean_version:
        return None

    url = f"https://api.deps.dev/v3/systems/pypi/packages/{package_name}/versions/{clean_version}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        licenses = data.get("licenses", [])
        if licenses:
            spdx = licenses[0] if isinstance(licenses[0], str) else licenses[0].get("license", "")
            result = {"license": spdx, "source": "deps.dev"}
            cache[cache_key] = result
            return result
    except Exception as e:
        logger.debug(f"deps.dev lookup failed for {package_name}: {e}")

    return None


def resolve_license_pypi(package_name: str, version: str, cache: dict) -> Optional[dict]:
    """Query PyPI JSON API for package license (fallback). Returns {"license": str, "source": "pypi"} or None."""
    cache_key = f"pypi:{package_name}:{version}"
    if cache_key in cache:
        return cache[cache_key]

    clean_version = version.lstrip("=<>~! ")
    url_parts = [f"https://pypi.org/pypi/{package_name}"]
    if clean_version:
        url_parts.append(clean_version)
    url = "/".join(url_parts) + "/json"

    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        raw_license = data.get("info", {}).get("license", "")
        if raw_license and raw_license.upper() not in ("UNKNOWN", "LICENSE", ""):
            normalized = normalize_license_text(raw_license)
            result = {"license": normalized, "source": "pypi"}
            cache[cache_key] = result
            return result
    except Exception as e:
        logger.debug(f"PyPI lookup failed for {package_name}: {e}")

    return None


def normalize_license_text(raw: str) -> str:
    """Normalize a free-text license string to an SPDX identifier."""
    if not raw:
        return "UNKNOWN"
    cleaned = raw.strip()
    lookup = cleaned.lower()
    if lookup in LICENSE_NORMALIZE_MAP:
        return LICENSE_NORMALIZE_MAP[lookup]
    # Check if it's already a valid SPDX-ish identifier
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", cleaned) and len(cleaned) < 40:
        return cleaned
    return cleaned


# ---------------------------------------------------------------------------
# SaaS context detection
# ---------------------------------------------------------------------------

def detect_saas_context(repo_root: Path, all_packages: dict[str, str]) -> bool:
    """Check for SaaS deployment indicators (web frameworks + Dockerfile)."""
    has_saas_framework = bool(SAAS_INDICATOR_PACKAGES & set(all_packages.keys()))
    has_dockerfile = (
        (repo_root / "Dockerfile").exists()
        or (repo_root / "docker-compose.yml").exists()
        or (repo_root / "docker-compose.yaml").exists()
    )
    return has_saas_framework or has_dockerfile


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def scan(repo_root: str | Path, hf_token: Optional[str] = None) -> dict:
    """
    Scan a repository for Python package license compliance issues.

    Returns:
        {
            "packages": {
                "package_name": {
                    "version": str,
                    "license": str | None,
                    "license_source": str,
                    "findings": [{"type", "severity", "detail", "remediation"}, ...]
                }
            }
        }
    """
    repo_root = Path(repo_root).resolve()
    cache = _load_cache()

    # 1. Collect all declared dependencies
    all_deps = collect_all_dependencies(repo_root)
    if not all_deps:
        logger.info("No Python dependency files found")
        return {"packages": {}}

    # 2. Resolve transitive dependency tree
    transitive_graph = resolve_transitive_deps()

    # 3. Detect SaaS deployment context
    is_saas = detect_saas_context(repo_root, all_deps)

    # 4. Process each package
    packages: dict[str, dict] = {}

    for pkg_name, version_spec in all_deps.items():
        pkg_data: dict = {
            "version": version_spec or "unspecified",
            "license": None,
            "license_source": "unknown",
            "findings": [],
        }

        canonical = pkg_name.lower().replace("-", "-")
        known = KNOWN_PROBLEMATIC_PACKAGES.get(canonical)

        # -- Check known problematic packages first --
        if known:
            # License override
            if "license_override" in known:
                pkg_data["license"] = known["license_override"]
                pkg_data["license_source"] = "hardcoded"

            # Primary finding (AGPL, GPL, etc.)
            if "finding" in known:
                finding = dict(known["finding"])
                # Adjust AGPL severity based on SaaS context
                if finding["type"] == "AGPL_SAAS" and not is_saas:
                    finding["severity"] = "HIGH"
                    finding["detail"] = (
                        f"{pkg_name} is licensed under AGPL-3.0. "
                        "No SaaS deployment indicators detected, but AGPL still requires "
                        "source disclosure on distribution."
                    )
                pkg_data["findings"].append(finding)

            # Transitive risk (e.g., python-slugify → Unidecode)
            if "transitive_risk" in known:
                pkg_data["findings"].append(dict(known["finding"]))
                # Set the transitive dep license info
                if not pkg_data["license"]:
                    pkg_data["license"] = known.get("transitive_license")
                    pkg_data["license_source"] = "hardcoded"

            # Bundled binary warning
            if "bundled_warning" in known:
                pkg_data["findings"].append(dict(known["bundled_warning"]))

        # -- Resolve license via APIs if not already overridden --
        if not pkg_data["license"]:
            resolved = resolve_license_deps_dev(pkg_name, version_spec, cache)
            if not resolved:
                resolved = resolve_license_pypi(pkg_name, version_spec, cache)

            if resolved:
                pkg_data["license"] = resolved["license"]
                pkg_data["license_source"] = resolved["source"]
            else:
                pkg_data["license_source"] = "unresolved"

        # -- Generate license-based findings --
        lic = pkg_data["license"]
        if lic:
            normalized = normalize_license_text(lic)
            pkg_data["license"] = normalized

            # Check for GPL family (if not already flagged by known overrides)
            if not pkg_data["findings"]:
                if normalized in GPL_FAMILY:
                    pkg_data["findings"].append({
                        "type": "COPYLEFT_STRONG",
                        "severity": "CRITICAL",
                        "detail": f"{pkg_name} is licensed under {normalized}. Distribution triggers copyleft.",
                        "remediation": "Replace with a permissively licensed alternative or consult legal counsel.",
                    })
                elif normalized in AGPL_FAMILY:
                    sev = "CRITICAL" if is_saas else "HIGH"
                    pkg_data["findings"].append({
                        "type": "AGPL_SAAS" if is_saas else "COPYLEFT_STRONG",
                        "severity": sev,
                        "detail": (
                            f"{pkg_name} is licensed under {normalized}. "
                            + ("SaaS deployment detected — network use triggers source disclosure." if is_saas
                               else "Distribution triggers copyleft obligations.")
                        ),
                        "remediation": "Obtain a commercial license or switch to an Apache-2.0 alternative.",
                    })
                elif normalized in LGPL_FAMILY:
                    pkg_data["findings"].append({
                        "type": "COPYLEFT_WEAK",
                        "severity": "INFO",
                        "detail": f"{pkg_name} is licensed under {normalized}. Dynamic linking is OK; static linking triggers copyleft.",
                        "remediation": "Ensure dynamic linking only. No action needed for standard pip installs.",
                    })
        else:
            # Missing or unknown license
            pkg_data["findings"].append({
                "type": "MISSING_LICENSE",
                "severity": "WARNING",
                "detail": f"{pkg_name}: no license metadata found via deps.dev or PyPI.",
                "remediation": "Manually verify the package license before commercial use.",
            })

        # -- PyPI metadata quality flags --
        if lic and lic.upper() in ("UNKNOWN", "LICENSE", ""):
            pkg_data["findings"].append({
                "type": "UNKNOWN_LICENSE",
                "severity": "WARNING",
                "detail": f'{pkg_name}: license metadata is "{lic}" — ambiguous or empty.',
                "remediation": "Check the package repository for a LICENSE file and verify manually.",
            })

        packages[pkg_name] = pkg_data

    # 5. Check transitive deps for more restrictive licenses
    for pkg_name, transitive_deps in transitive_graph.items():
        if pkg_name not in packages:
            continue
        for tdep in transitive_deps:
            if tdep in packages:
                tdep_lic = packages[tdep].get("license", "")
                if tdep_lic and tdep_lic in (GPL_FAMILY | AGPL_FAMILY):
                    parent_lic = packages[pkg_name].get("license", "")
                    if parent_lic and parent_lic not in (GPL_FAMILY | AGPL_FAMILY):
                        # Already flagged by known overrides? Skip
                        existing_types = {f["type"] for f in packages[pkg_name].get("findings", [])}
                        if "TRANSITIVE_GPL" not in existing_types:
                            packages[pkg_name]["findings"].append({
                                "type": "TRANSITIVE_GPL",
                                "severity": "CRITICAL",
                                "detail": (
                                    f"{pkg_name} ({parent_lic}) transitively depends on "
                                    f"{tdep} ({tdep_lic}). GPL contaminates through the dependency chain."
                                ),
                                "remediation": f"Replace {tdep} with a permissively licensed alternative.",
                            })

    _save_cache(cache)

    return {"packages": packages}
