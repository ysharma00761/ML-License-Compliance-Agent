# Product Requirements Document
## ML License Compliance Agent — GitLab AI Hackathon
**Deadline:** March 25, 2026 @ 11:00am PDT

---

## Overview

This project is a GitLab Duo Agent that automatically audits ML projects for license compliance violations across three dimensions: Python package dependencies, Hugging Face models, and training datasets. It runs as a CI/CD job, produces a CycloneDX ML Bill of Materials (ML-BOM), posts findings as MR comments, and blocks pipelines on critical violations. The agent is powered by Anthropic Claude via the GitLab Duo Agent Platform.

**The core problem it solves:** No existing tool (FOSSA, Snyk, Black Duck) checks code packages, AI models, and training datasets together in a single CI/CD pass. This agent fills that gap.

---

## Team Assignments

| Person | Role | Tasks |
|--------|------|-------|
| **Technical Person A** | Scanner + CI/CD | 2, 4, 7, 8, 10 |
| **Technical Person B** | Scanner + Output | 1, 3, 5, 6, 11 |
| **Non-Technical Person** | Demo + Docs + Submission | 9, 12, 13, 14 |

---

## Technical Person A — Scanner + CI/CD

### Task 2: Python Package License Scanner
**Goal:** Parse all Python dependency files in the target repo, resolve the full transitive dependency tree, and flag any packages with problematic licenses.

**Why it matters:** A project can depend on `python-slugify` (MIT) which transitively pulls in `Unidecode` (GPLv2+) — the direct dependency looks clean but the transitive one is a legal violation. This scanner catches what `pip install` hides.

**What to build:**
- A multi-format parser that reads `requirements.txt`, `pyproject.toml`, and `Pipfile` to extract all declared dependencies and their pinned versions.
- A transitive dependency resolver using `pipdeptree` that builds a full dependency graph, not just the top-level packages.
- A license resolution layer that queries the `deps.dev` API (with PyPI JSON API as fallback) to get the SPDX license expression for every package. Results should be cached locally to avoid hitting rate limits during development.
- A hardcoded override registry for packages known to have incorrect or incomplete license metadata — covering `python-slugify`, `ultralytics`, `PyQt5/6`, `torch` GPU wheels, `opencv-python`, `bitsandbytes`, and `torchaudio`.
- A SaaS deployment context detector that checks whether AGPL packages are being used alongside `fastapi`, `flask`, `uvicorn`, or a `Dockerfile` — if so, escalates to CRITICAL severity.
- A metadata quality checker that flags packages with empty, `"UNKNOWN"`, or ambiguous license fields as WARNINGs.

**Output:** A structured dict of `{package: {version, license, depends_on, depended_by, findings[]}}` passed to the policy engine.

---

### Task 4: Training Dataset License Scanner
**Goal:** Extract all Hugging Face dataset references from the codebase, resolve their licenses, and flag datasets whose terms conflict with the project's intended use (commercial, research-only, ShareAlike).

**Why it matters:** `lmsys/chatbot_arena_conversations` is CC-BY-NC-4.0 — using it to train a commercial model is a clear violation. `bigcode/the-stack` contains files under GPL/AGPL. These violations are invisible without scanning.

**What to build:**
- A regex-based extractor that finds all `load_dataset("dataset_id")` calls in Python files and dataset references in YAML/JSON config files. Must handle the two-argument form (`load_dataset("dataset", "config")`) and flag dynamic/variable references as UNRESOLVED.
- A license resolver using `huggingface_hub`'s `api.dataset_info()` to look up license metadata for each dataset ID. Responses should be cached locally.
- A hardcoded registry of well-known datasets with complex or multi-layered licenses: `common_crawl`, `laion/laion5B`, `EleutherAI/pile`, `wikipedia`, `imagenet-1k`, `ms-coco`, `bigcode/the-stack`, `NVlabs/ffhq-dataset`, and `lmsys/chatbot_arena_conversations`.
- Violation logic: CC-BY-NC → HIGH, CC-BY-SA → MEDIUM, research-only in commercial context → HIGH, missing license → WARNING.

**Output:** A list of dataset findings passed to the policy engine.

---

### Task 7: GitLab CI/CD Integration
**Goal:** Package the scanner as a GitLab CI/CD job so it runs automatically on every pipeline, surfaces findings in the security dashboard, and blocks MRs on critical violations.

**Why it matters:** The scanner only has value if it runs without any manual invocation. CI/CD integration makes compliance enforcement automatic and org-wide.

**What to build:**
- A `.gitlab-ci.yml` job definition for `ml-license-compliance` in a `compliance` stage. Use `python:3.11-slim` as the base image. Install all scanner dependencies in `before_script`. Pass `$HF_TOKEN` and `$GITLAB_TOKEN` from masked CI/CD variables.
- Artifact configuration: upload `ml-sbom.json` as a `cyclonedx` report artifact (so GitLab parses it into the security dashboard) and `compliance-report.md` as a downloadable artifact. Expire after 30 days.
- MR comment posting: detect `$CI_MERGE_REQUEST_IID` and use the GitLab API to post a formatted Markdown comment with findings grouped by severity using emoji indicators (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, ⚠️ WARNING). Include remediation links.
- Optional: a Merge Request Approval Policy requiring 2 security approvers when the compliance job fails.
- Optional: a Pipeline Execution Policy (GitLab 17.9+) that injects the compliance job into all group project pipelines with zero configuration required from individual teams.

**Output:** Working `.gitlab-ci.yml`, MR comment integration, artifact uploads.

---

### Task 8: GitLab Duo Agent Configuration
**Goal:** Create the GitLab Duo Agent YAML so the compliance scanner can be invoked interactively from GitLab Duo Chat — this is required by hackathon rules.

**Why it matters:** Hackathon rules require at least one custom public agent or flow. The agent also enables ad-hoc compliance checks without waiting for a CI/CD run.

**What to build:**
- Copy `.agent.yml.template` to `agent/ml-compliance-agent.yml` and configure: agent name, description, and system prompt covering scan scope, output format, violation categories, severity levels, and remediation guidance.
- Enable agent capabilities: file reading (to scan Python files), web/API calls (for Hugging Face Hub API), GitLab API access (for MR comments), and artifact creation (for CycloneDX BOM output).
- Write detailed prompt instructions for each scan type so the agent knows how to handle `requirements.txt`, model IDs, dataset IDs, policy classification, and report generation.
- Commit, verify the CI pipeline passes schema validation, and create a semver git tag to publish the agent to the GitLab catalog.
- Verify the agent appears in the GitLab Duo Chat agent selector and test it against the demo repo.

**Output:** Published agent in the GitLab catalog, verified via Duo Chat.

---

### Task 10: Anthropic / Claude Integration
**Goal:** Integrate Claude (via the GitLab Duo Agent Platform) to add natural language intelligence on top of the rule-based scanner — qualifying for the "Most Impactful on GitLab & Anthropic" prize track.

**Why it matters:** Rule-based scanners can't interpret ambiguous license text, assess contextual risk, or explain findings to non-legal engineers. Claude fills these gaps and is required for the $10,000 Anthropic prize track.

**What to build:**
- Use Claude as a tool call inside the Duo Agent YAML (not via direct `anthropic` SDK in CI scripts — the hackathon group provides model access through the agent platform).
- License text interpreter: send raw LICENSE file text to Claude to extract the license type when the metadata is missing or ambiguous.
- Plain-English risk summaries: call Claude to explain each finding in language a non-legal engineer can act on.
- Context-aware remediation: provide Claude with the project type (from README/code) and ask for tailored replacement recommendations.
- OpenRAIL analysis: send the project description + OpenRAIL prohibited use cases to Claude to assess whether the project's apparent purpose conflicts with the model's behavioral restrictions. Output as a MEDIUM finding with Claude's reasoning.
- Executive summary: feed all findings to Claude and generate a non-technical summary for `compliance-report.md`.
- Document Claude integration in the README as "Powered by Anthropic Claude via GitLab Duo Agent Platform".

**Output:** Claude-powered analysis woven into the compliance report and agent responses.

---

## Technical Person B — Scanner + Output

### Task 1: GitLab Project Setup & Configuration
**Goal:** Get the shared development environment fully configured so both technical contributors can start building immediately without environment-related blockers.

**Why it matters:** This is the foundation everything else depends on. Mismatched environments or missing CI/CD variables will waste time for the whole team.

**What to build:**
- Set the GitLab Duo default namespace to "GitLab AI Hackathon" and confirm group access at `gitlab.com`.
- Clone the repo, create a Python virtual environment, and install all core dependencies: `huggingface_hub`, `pip-licenses`, `pipdeptree`, `cyclonedx-python`, `requests`, `PyYAML`.
- Add `HF_TOKEN` and `GITLAB_TOKEN` as masked CI/CD variables in the project settings.
- Create the agreed folder structure: `scanner/`, `policy/`, `output/`, `agent/`, `demo-repo/`, `tests/`.

**Output:** A runnable local dev environment and a scaffolded repo that both technical contributors can clone and start from.

---

### Task 3: Hugging Face Model License Scanner
**Goal:** Extract all Hugging Face model references from the codebase, resolve their licenses via the HF Hub API, and flag models whose licenses impose obligations the project may not be meeting.

**Why it matters:** `meta-llama/Meta-Llama-3-8B-Instruct` has a custom restricted license with an attribution requirement, a 700M MAU threshold, and an anti-distillation clause. None of this is visible from `pip install`. Most ML engineers don't know these obligations exist.

**What to build:**
- A regex-based code scanner that extracts model IDs from `.from_pretrained()`, `pipeline(model=...)`, and `SentenceTransformer()` calls across all `*.py` files. Must flag dynamic/variable model references (e.g., `from_pretrained(model_name)`) as UNRESOLVED requiring manual review.
- A config file scanner that looks for model references in YAML, JSON, `.env`, shell scripts, and Dockerfiles.
- A license resolver using `huggingface_hub`'s `api.model_info()` to get license metadata. Must handle `license: other` (extract `license_name` and `license_link`), 404s for private models, and rate limits with exponential backoff. Cache responses locally.
- A custom AI license taxonomy mapping non-SPDX licenses to compliance categories: `llama2/3` → `CUSTOM_RESTRICTED`, `openrail/openrail++` → `RESTRICTED_USE`, `agpl-3.0` → `COPYLEFT_STRONG`, standard permissive licenses → `PERMISSIVE`, missing → `UNKNOWN_RISK`.
- Llama-specific checks: verify "Built with Meta Llama" attribution exists in the README, flag `distill.py` or training scripts used alongside a Llama model as a potential anti-distillation violation.
- OpenRAIL flagging: enumerate prohibited use cases (surveillance, military, disinformation, discriminatory profiling) as WARNING items requiring human review.

**Output:** A structured list of model findings passed to the policy engine.

---

### Task 5: Policy Engine
**Goal:** Take all findings from the three scanners and apply org-level rules to produce a severity-ranked, deduplicated list of violations with concrete remediation steps.

**Why it matters:** Raw scanner output is noisy. The policy engine is what turns "this package has a GPL license" into "this is a CRITICAL violation because you're shipping a commercial SaaS product and must either relicense or replace the dependency."

**What to build:**
- A YAML-based policy configuration file (`policy/compliance-policy.yml`) with: `allowed_licenses`, `denied_licenses` with severity, `review_required_licenses`, and boolean flags for `commercial_use`, `saas_deployment`, and `require_attribution_check`.
- A severity classification engine with five levels: CRITICAL (GPL/AGPL in commercial distributed app), HIGH (NC dataset in commercial training, missing Llama attribution), MEDIUM (CC-BY-SA ShareAlike risk, OpenRAIL behavioral restrictions), WARNING (missing license metadata, ambiguous strings, unresolved references), INFO (permissive license with attribution requirement).
- A remediation recommendation engine with specific, actionable fixes for each known violation type: replacement packages, license purchase links, attribution wording, and legal consultation guidance.
- CI/CD exit code logic: exit `1` on any CRITICAL finding (always), exit `1` on HIGH findings (configurable), exit `0` for WARNING/INFO-only runs.

**Output:** A ranked findings list consumed by the BOM generator and CI/CD integration.

---

### Task 6: CycloneDX ML-BOM Generator
**Goal:** Produce a machine-readable CycloneDX v1.5 ML Bill of Materials and a human-readable compliance report from all scanner findings — these are the primary output artifacts of the agent.

**Why it matters:** GitLab's security dashboard natively parses CycloneDX BOM artifacts. Without this, findings don't appear in the dashboard and the MR blocking integration doesn't work. The BOM is also the submission artifact judges will evaluate.

**What to build:**
- A CycloneDX v1.5 BOM structure with proper `metadata` (project name, version, timestamp, tool attribution).
- Component mappings for all three asset types:
  - Python packages → `type: library` with `purl: pkg:pypi/{name}@{version}` and SPDX license expression.
  - HF models → `type: machine-learning-model` with `purl: pkg:huggingface/{org}/{model}@{revision}`, model card external reference, and use-restriction notes for OpenRAIL/Llama models.
  - Datasets → `type: data` with `purl: pkg:huggingface/{dataset_id}`, license, and commercial eligibility.
- A compliance findings section encoding each policy violation with: ID, severity, description, recommendation, and affected component reference.
- Two output files: `ml-sbom.json` (machine-readable, parsed by GitLab) and `compliance-report.md` (human-readable, grouped by severity with an executive summary at the top).
- BOM validation against the CycloneDX schema before writing (using `cyclonedx-py` validators).

**Output:** `ml-sbom.json` and `compliance-report.md` written to the repo root.

---

### Task 11: Testing
**Goal:** Ensure all scanner modules behave correctly in isolation and produce the expected end-to-end output against the demo repo.

**Why it matters:** The demo depends on specific violations being caught. If the scanner silently misses a violation during the live demo, it's a failed submission. Tests lock in the expected behavior before demo day.

**What to build:**
- Unit tests for the Python package scanner: `requirements.txt` parser with varied pin formats, `deps.dev` API response parsing (mocked), GPL transitive dep detection (`python-slugify → Unidecode`), and AGPL + SaaS indicator detection (`ultralytics + fastapi`).
- Unit tests for the model scanner: `from_pretrained()` regex extraction, dynamic reference detection (must flag as UNRESOLVED, not silently skip), HF API response parsing (mocked), and license taxonomy mapping.
- Unit tests for the dataset scanner: `load_dataset()` regex with single and two-argument forms, CC-BY-NC detection and HIGH severity classification, and well-known dataset registry lookups.
- Integration test: run the full scanner against `demo-repo/` and assert all expected violations are found, `ml-sbom.json` is valid CycloneDX v1.5, exit code is `1`, and the MR comment would be generated correctly (mock GitLab API).
- **Critical constraint:** Tests must be read-only against `demo-repo/`. Never auto-fix violations during test runs — `demo-repo/` must remain intentionally broken for the demo.

**Output:** Passing test suite in `tests/` that covers all scanner modules and the full end-to-end flow.

---

## Non-Technical Person — Demo + Docs + Submission

### Task 9: Demo Repository Setup
**Goal:** Create a realistic-looking ML inference repo inside `demo-repo/` with real license violations planted in it — this is what gets scanned live during the demo.

**Why it matters:** Judges watch a 3-minute video. The demo needs to show real violations being caught in real code that looks like something a team would actually build. Fake or toy examples won't be convincing.

**What to create:**
- `demo-repo/requirements.txt` including `python-slugify==8.0.1`, `torch`, `transformers`, `fastapi`, `uvicorn`, and `ultralytics==8.0.200`. Do NOT add `text-unidecode` (the scanner should catch and recommend it).
- `demo-repo/app.py` — a simple FastAPI inference server (provides SaaS deployment context for AGPL detection).
- `demo-repo/inference.py` — loads `meta-llama/Meta-Llama-3-8B-Instruct` via `AutoModelForCausalLM.from_pretrained()`.
- `demo-repo/train_data.py` — loads `lmsys/chatbot_arena_conversations` via `load_dataset()` (CC-BY-NC-4.0 violation).
- `demo-repo/distill.py` — a script using Llama outputs to train a smaller non-Llama model (anti-distillation clause violation).
- `demo-repo/detect.py` — a FastAPI endpoint using YOLOv8 for object detection via `ultralytics`.
- `demo-repo/Dockerfile` — containerized deployment (confirms SaaS context for AGPL escalation).
- Do NOT add "Built with Meta Llama 3" to any README (attribution violation must remain present).
- Verify all 5+ violations exist by running the scanner manually with technical teammates before the demo.

> **Note:** The technical teammates will scaffold the Python file templates. This task is about assembling the full demo scenario, verifying the violations match the demo script, and ensuring nothing is accidentally fixed.

---

### Task 12: Documentation & README
**Goal:** Write clear, compelling documentation that explains what the agent does, how to use it, and why it's unique — both for judges evaluating the submission and for developers who might adopt it.

**What to write:**
- `README.md` containing: a one-sentence description of what the agent does and why it's unique; a table comparing this agent to FOSSA, Snyk, and Black Duck (showing the gap it fills); installation and usage instructions for both local runs and CI/CD; a `compliance-policy.yml` configuration guide; example output for each of the three demo scenarios; an architecture diagram (ASCII or embedded image); and a "Powered by Anthropic Claude via GitLab Duo Agent Platform" note for the Anthropic prize track.
- Add an Apache-2.0 `LICENSE` file to the repo root (required for submission — must be auto-detected and visible in GitLab's Project Information section).
- An agent usage guide explaining how to invoke the agent from GitLab Duo Chat.
- A CI/CD integration guide explaining how an existing project can add the compliance job to their pipeline.

---

### Task 13: Demo Video Production
**Goal:** Record a compelling 3-minute demo video that shows the agent catching real violations and upload it publicly to YouTube for the Devpost submission.

**Script (follow this exactly — judges will not watch beyond 3:00):**
- **0:00–0:10** — Hook: *"65% of Hugging Face models have no license. No tool checks model + dataset + package licenses together. Until now."*
- **0:10–0:40** — Demo 1 (GPL Trap): Show `requirements.txt` with `python-slugify`. Run scanner. Show CRITICAL: Unidecode (GPLv2+) flagged, dependency chain visible, `text-unidecode` recommended.
- **0:40–2:10** — Demo 2 (Llama Triple Violation): Show `inference.py`, `train_data.py`, `distill.py`. Run scanner. Show 3 violations: missing attribution, distillation clause, CC-BY-NC dataset. Show specific license clause references in output.
- **2:10–2:40** — Show CycloneDX ML-BOM in GitLab's security dashboard. Show MR blocked with CRITICAL findings in the MR comment.
- **2:40–3:00** — Closing: *"Before: 3 tools, manual review. After: one CI/CD job, zero missed violations."*

**Recording requirements:** 1080p minimum, screen recorder (QuickTime or OBS), live narration or voiceover, trim dead air before upload.

**Upload:** YouTube as **Public** (not Unlisted). Title: *"ML License Compliance Agent — GitLab AI Hackathon Demo"*. Save the URL for Devpost.

---

### Task 14: Hackathon Submission
**Goal:** Submit the project on Devpost before the March 25 deadline with all required fields filled out correctly.

**Pre-submission checklist:**
- GitLab repo is public and in the AI Hackathon group
- All source code, assets, and instructions are in the repo
- License is Apache-2.0 and visible in the GitLab Project Information section
- At least one custom public agent is tagged and published to the GitLab catalog
- Demo video is on YouTube as Public and is under 3 minutes
- CI pipeline passes (agent YAML schema validates)

**Devpost write-up (cover all of these points):**
- The compliance gap: no tool checks code packages + AI models + training datasets in a single pass
- The three violation types the demo catches: GPL transitive trap, Llama triple violation, AGPL SaaS bomb
- CycloneDX ML-BOM output and GitLab security dashboard integration
- EU AI Act enforcement context (August 2025) for regulatory urgency
- Anthropic/Claude integration via GitLab Duo Agent Platform (for Anthropic prize track eligibility)
- First-to-market positioning: no other tool does unified ML compliance scanning in CI/CD

**Submit:** Go to the hackathon Devpost page → "Submit Project" → paste GitLab repo URL, YouTube URL, and project description → verify all fields → submit → screenshot the confirmation.

---

## Severity Reference

| Level | Meaning | Example |
|-------|---------|---------|
| **CRITICAL** | Must fix before shipping | GPL/AGPL in commercial distributed app or SaaS without source disclosure |
| **HIGH** | Clear violation, high legal risk | NC-licensed dataset used in commercial training; missing Llama attribution |
| **MEDIUM** | Risk requiring legal review | CC-BY-SA ShareAlike propagation; OpenRAIL behavioral restriction |
| **WARNING** | Missing info, manual review needed | Empty/unknown license metadata; unresolved dynamic model reference |
| **INFO** | Informational only | Permissive license with attribution requirement; Llama 700M MAU threshold |

---

## Dependency Order

```
Person B (Task 1: Setup) ─────────────────────────────────────┐
Person A (Task 2: Python Scanner) ──────────────────────────┐ │
Person A (Task 4: Dataset Scanner) ─────────────────────────┤ │
Person B (Task 3: Model Scanner) ───────────────────────────┤ │
                                                            ▼ ▼
                                              Person B (Task 5: Policy Engine)
                                                            │
                                                            ▼
                                              Person B (Task 6: BOM Generator)
                                                            │
                                              Person A (Task 7: CI/CD) ◄──────┐
                                              Person A (Task 8: Agent) ◄──────┤
                                              Person A (Task 10: Claude) ◄────┤
                                              Person B (Task 11: Testing) ◄───┘
                                                            │
                                                            ▼
                                         Non-Tech (Task 9: Demo Repo) ← needs scanner working
                                         Non-Tech (Task 12: Docs) ← can start anytime
                                         Non-Tech (Task 13: Video) ← needs demo repo + CI working
                                         Non-Tech (Task 14: Submit) ← last
```

Tasks 12 and parts of Task 9 (file creation) can start immediately in parallel.