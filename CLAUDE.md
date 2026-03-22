# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

ML License Compliance Agent for the GitLab AI Hackathon (deadline: March 25, 2026). The agent audits ML projects for license violations across three dimensions: Python packages, Hugging Face models, and training datasets. It runs in GitLab CI/CD, produces a CycloneDX ML-BOM, and blocks MRs on critical violations.

## Repository Layout

```
agents/agent.yml          # GitLab Duo Agent config (must stay valid YAML per CI schema check)
flows/flow.yml            # GitLab Duo Flow config (same schema validation requirement)
scanner/                  # (to be created) Python scanner modules
policy/                   # (to be created) compliance-policy.yml + engine
output/                   # (to be created) CycloneDX BOM + report generators
demo-repo/                # (to be created) intentionally broken ML repo for demo
tests/                    # (to be created) unit + integration tests
PRD.md                    # Full task assignments and specifications per person
TODO.md                   # Build checklist — update checkboxes as tasks complete
```

## Branch Strategy

- `main` — upstream base
- `work` — shared integration branch; PRs merge here
- `archit` — your working branch; pull from `work` regularly

Always work on `archit`, merge to `work`.

## GitLab Agent & Flow Files

After any edit to `agents/agent.yml` or `flows/flow.yml`:
1. Commit and push — a CI pipeline runs schema validation automatically
2. If the pipeline fails, fix the YAML before proceeding
3. To publish to the GitLab catalog, create a semver git tag (e.g., `git tag v0.1.0 && git push --tags`)

The agent YAML supports these tools (see full list in the comment inside `agent.yml`):
`read_file`, `read_files`, and others at the linked catalog URL.

## Core Architecture (what to build)

The scanner has a strict pipeline order — each stage feeds the next:

1. **Scanners** (Tasks 2, 3, 4) — independent, run in parallel
   - Python pkg scanner: parse `requirements*.txt` / `pyproject.toml` / `Pipfile` → resolve transitive deps via `pipdeptree` → query `deps.dev` API for licenses
   - Model scanner: regex over `*.py` files for `.from_pretrained()`, `pipeline(model=...)`, `SentenceTransformer()` → `huggingface_hub.api.model_info()`
   - Dataset scanner: regex for `load_dataset()` → `huggingface_hub.api.dataset_info()`

2. **Policy Engine** (Task 5) — consumes all scanner output, applies `policy/compliance-policy.yml` rules, outputs severity-ranked findings (CRITICAL / HIGH / MEDIUM / WARNING / INFO)

3. **BOM Generator** (Task 6) — produces `ml-sbom.json` (CycloneDX v1.5) and `compliance-report.md`

4. **CI/CD + Agent** (Tasks 7, 8) — `.gitlab-ci.yml` uploads BOM as `cyclonedx` artifact, posts MR comment, exits `1` on CRITICAL

## Key Technical Decisions

- Use `huggingface_hub` Python library (not raw REST) for model/dataset lookups
- Output CycloneDX v1.5 (not SPDX) — GitLab's security dashboard already parses it
- Cache HF API responses locally — model licenses rarely change, rate limits are real
- Flag dynamic model references (`from_pretrained(variable)`) as UNRESOLVED, never silently skip
- Claude is invoked via the GitLab Duo Agent Platform (not direct `anthropic` SDK in CI scripts)

## Demo Repo Constraint

`demo-repo/` must remain intentionally broken at all times. Tests are read-only against it. Never auto-fix violations in `demo-repo/` — the scanner demo depends on them being present.

## Severity Quick Reference

| Level | Trigger |
|-------|---------|
| CRITICAL | GPL/AGPL in commercial/SaaS app |
| HIGH | NC dataset in commercial training; missing Llama attribution |
| MEDIUM | CC-BY-SA ShareAlike risk; OpenRAIL behavioral restriction |
| WARNING | Missing/unknown license metadata; unresolved dynamic reference |
| INFO | Permissive license with attribution; Llama 700M MAU threshold |

## TODO Tracking

Update `TODO.md` checkboxes as tasks are completed. This is the shared progress tracker for the whole team.
