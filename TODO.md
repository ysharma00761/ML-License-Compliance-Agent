# GitLab AI Hackathon — ML License Compliance Agent
## Deadline: March 25, 2026 @ 11:00am PDT

---

## Task 1: GitLab Project Setup & Configuration

- [ ] **1.1** Set Default GitLab Duo namespace to "GitLab AI Hackathon" in settings (required to test agent/flow)
- [ ] **1.2** Confirm access to the GitLab AI Hackathon group project at `gitlab.com`
- [ ] **1.3** Review the participant template (agent + flow templates) in the project
- [ ] **1.4** Set up local development environment
  - [ ] **1.4.1** Clone the hackathon project repo locally
  - [ ] **1.4.2** Create a Python virtual environment (`python -m venv .venv`)
  - [ ] **1.4.3** Install core dependencies: `huggingface_hub`, `pip-licenses`, `pipdeptree`, `cyclonedx-python`, `requests`, `PyYAML`
- [ ] **1.5** Configure GitLab CI/CD variables in the project
  - [ ] **1.5.1** Add `HF_TOKEN` (Hugging Face API token) as a masked CI/CD variable
  - [ ] **1.5.2** Add `GITLAB_TOKEN` (personal access token with `read_api` scope) as masked CI/CD variable
- [ ] **1.6** Decide on repository structure and create folder layout:
  - [ ] **1.6.1** `scanner/` — core scanning logic
  - [ ] **1.6.2** `policy/` — policy engine and license maps
  - [ ] **1.6.3** `output/` — CycloneDX BOM generation
  - [ ] **1.6.4** `agent/` — GitLab Duo Agent YAML config
  - [ ] **1.6.5** `demo-repo/` — planted violation examples for demo
  - [ ] **1.6.6** `tests/` — unit tests for each scanner module

---

## Task 2: Python Package License Scanner

> Covers: Transitive GPL contamination, AGPL SaaS trap, bundled binary detection

- [ ] **2.1** Build `requirements.txt` / `Pipfile` / `pyproject.toml` parser
  - [ ] **2.1.1** Parse `requirements.txt` — extract package name and version (handle `==`, `>=`, `~=`, no version)
  - [ ] **2.1.2** Parse `pyproject.toml` — extract `[project.dependencies]` and `[tool.poetry.dependencies]` sections
  - [ ] **2.1.3** Parse `Pipfile` — extract `[packages]` and `[dev-packages]`
  - [ ] **2.1.4** Handle multiple requirements files (`requirements-dev.txt`, `requirements-test.txt`, etc.)
- [ ] **2.2** Resolve transitive dependency tree
  - [ ] **2.2.1** Use `pipdeptree` to build full dependency graph (direct + transitive)
  - [ ] **2.2.2** Store as a dict: `{package: {version, license, depends_on: [], depended_by: []}}`
  - [ ] **2.2.3** Flag packages where a transitive dep has a more restrictive license than the direct dep
- [ ] **2.3** License resolution via deps.dev API
  - [ ] **2.3.1** Call `GET https://api.deps.dev/v3/systems/pypi/packages/{name}/versions/{version}` for each package
  - [ ] **2.3.2** Extract SPDX license expression from API response
  - [ ] **2.3.3** Fallback to PyPI JSON API (`https://pypi.org/pypi/{name}/{version}/json`) if deps.dev fails
  - [ ] **2.3.4** Normalize free-text license strings to SPDX (e.g., "BSD" → "BSD-3-Clause", "Apache" → "Apache-2.0")
  - [ ] **2.3.5** Cache responses locally (JSON file) to avoid repeated API calls during development
- [ ] **2.4** Build known-problematic package registry (hardcoded overrides for known metadata errors)
  - [ ] **2.4.1** `python-slugify` → flag transitive dep `Unidecode` (GPLv2+); recommend `text-unidecode`
  - [ ] **2.4.2** `ultralytics` (YOLOv8) → AGPL-3.0; flag SaaS deployment risk
  - [ ] **2.4.3** `PyQt5` / `PyQt6` → GPL-3.0; recommend `PySide2`/`PySide6` (LGPL)
  - [ ] **2.4.4** `torch` GPU wheels → note bundled NVIDIA proprietary EULA binaries
  - [ ] **2.4.5** `opencv-python` (non-headless) → note bundled FFmpeg (LGPLv2.1) and Qt5 (LGPLv3)
  - [ ] **2.4.6** `bitsandbytes` → note multi-license portions despite MIT declaration
  - [ ] **2.4.7** `torchaudio` with FFmpeg `--enable-gpl` → runtime license becomes GPL (flag as WARNING)
- [ ] **2.5** SaaS deployment context detector
  - [ ] **2.5.1** Scan for `fastapi`, `flask`, `uvicorn`, `gunicorn`, `starlette` in dependencies (API server = SaaS indicator)
  - [ ] **2.5.2** Check for `Dockerfile` or `docker-compose.yml` in the repo root
  - [ ] **2.5.3** If AGPL package + SaaS indicators detected → escalate to CRITICAL severity
- [ ] **2.6** PyPI metadata quality flags
  - [ ] **2.6.1** Flag packages where license is `"UNKNOWN"`, empty, or just `"LICENSE"` as WARNING
  - [ ] **2.6.2** Flag packages using ambiguous Trove classifiers (e.g., "BSD License" — is it BSD-2 or BSD-3?) as WARNING
  - [ ] **2.6.3** Cross-reference `License` field against `License :: OSI Approved` classifiers for consistency check

---

## Task 3: Hugging Face Model License Scanner

> Covers: Llama license obligations, OpenRAIL use restrictions, missing license detection

- [ ] **3.1** Build Python code scanner to extract model references
  - [ ] **3.1.1** Implement regex patterns for all major HF loading patterns:
    - `\.from_pretrained\(\s*["']([a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+)["']`
    - `pipeline\([^)]*model\s*=\s*["']([a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+)["']`
    - `SentenceTransformer\(\s*["']([a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+)["']`
  - [ ] **3.1.2** Scan all `*.py` files recursively in the repo
  - [ ] **3.1.3** Deduplicate model IDs (same model referenced in multiple files → one entry)
  - [ ] **3.1.4** Flag dynamic/variable model references (e.g., `from_pretrained(model_name)`) as "UNRESOLVED — manual review needed"
  - [ ] **3.1.5** Detect f-string model references (e.g., `from_pretrained(f"{org}/{model}")`) and flag as UNRESOLVED
- [ ] **3.2** Build config file scanner for model references
  - [ ] **3.2.1** Scan YAML files for keys: `model_name_or_path`, `pretrained_model_name_or_path`, `base_model`
  - [ ] **3.2.2** Scan JSON files for same keys
  - [ ] **3.2.3** Scan `.env` files for `MODEL_NAME`, `HF_MODEL_ID`, `BASE_MODEL` keys
  - [ ] **3.2.4** Scan shell scripts and Dockerfiles for `HF_MODEL` env vars or `huggingface-cli download` calls
- [ ] **3.3** Resolve model licenses via Hugging Face Hub API
  - [ ] **3.3.1** Use `huggingface_hub` library: `api.model_info(model_id, cardData=True)`
  - [ ] **3.3.2** Extract license from `info.cardData["license"]` (primary) and `info.tags` (fallback)
  - [ ] **3.3.3** Handle `license: other` → extract `license_name` and `license_link` from card YAML
  - [ ] **3.3.4** Handle 404 (model not found / private) → flag as WARNING with note about private model
  - [ ] **3.3.5** Handle rate limits → implement exponential backoff with `HF_TOKEN` authentication
  - [ ] **3.3.6** Cache API responses to a local JSON file (model licenses rarely change)
- [ ] **3.4** Build custom AI license taxonomy (non-SPDX → compliance category mapping)
  - [ ] **3.4.1** `llama2` → `CUSTOM_RESTRICTED` (700M MAU threshold, attribution required)
  - [ ] **3.4.2** `llama3` → `CUSTOM_RESTRICTED` (700M MAU threshold, attribution required, anti-competition clause for distillation)
  - [ ] **3.4.3** `llama3.1`, `llama3.2`, `llama3.3` → `CUSTOM_RESTRICTED` (anti-competition clause relaxed for 3.1+, verify)
  - [ ] **3.4.4** `gemma` → `CUSTOM_RESTRICTED` (use restrictions + redistribution requirements)
  - [ ] **3.4.5** `openrail` / `openrail++` / `creativeml-openrail-m` → `RESTRICTED_USE` (behavioral restrictions, propagate to derivatives)
  - [ ] **3.4.6** `bigscience-bloom-rail-1.0` → `RESTRICTED_USE` (prohibits surveillance, disinformation, discriminatory profiling)
  - [ ] **3.4.7** `agpl-3.0` → `COPYLEFT_STRONG` (SaaS network clause triggers source disclosure)
  - [ ] **3.4.8** `gpl-2.0`, `gpl-3.0` → `COPYLEFT_STRONG` (distribution triggers copyleft)
  - [ ] **3.4.9** `lgpl-2.1`, `lgpl-3.0` → `COPYLEFT_WEAK` (dynamic linking OK, static linking triggers)
  - [ ] **3.4.10** `apache-2.0`, `mit`, `bsd-3-clause`, `bsd-2-clause` → `PERMISSIVE`
  - [ ] **3.4.11** No license / missing → `UNKNOWN_RISK` (flag as WARNING, requires manual review)
- [ ] **3.5** Implement Llama-specific violation checks
  - [ ] **3.5.1** If `meta-llama/` model detected → check repo for "Built with Meta Llama" attribution string in README or LICENSE
  - [ ] **3.5.2** If `meta-llama/Meta-Llama-3*` detected + `distill.py` or training script found → flag potential anti-distillation violation (Section 1.b.v)
  - [ ] **3.5.3** Flag the 700M MAU threshold clause as informational (cannot auto-detect user count)
- [ ] **3.6** Implement OpenRAIL flagging
  - [ ] **3.6.1** If OpenRAIL model detected → enumerate specific prohibited use cases (surveillance, military, disinformation, discriminatory profiling) as WARNING items requiring human review
  - [ ] **3.6.2** Flag that behavioral restrictions propagate to all fine-tuned derivatives and downstream deployments

---

## Task 4: Training Dataset License Scanner

> Covers: CC-BY-NC commercial trap, CC-BY-SA ShareAlike propagation, research-only dataset misuse

- [ ] **4.1** Build dataset reference extractor
  - [ ] **4.1.1** Implement regex for `load_dataset\(\s*["']([a-zA-Z0-9_-]+(?:/[a-zA-Z0-9._-]+)?)["']`
  - [ ] **4.1.2** Handle two-argument form: `load_dataset("dataset", "config", split="train")` — extract first arg as dataset ID
  - [ ] **4.1.3** Scan YAML/JSON config files for `dataset_name`, `dataset_path`, `train_dataset`, `eval_dataset` keys
  - [ ] **4.1.4** Deduplicate dataset IDs across all files
  - [ ] **4.1.5** Flag variable/dynamic dataset references as UNRESOLVED
- [ ] **4.2** Resolve dataset licenses via Hugging Face Hub API
  - [ ] **4.2.1** Call `api.dataset_info(dataset_id)` using `huggingface_hub`
  - [ ] **4.2.2** Extract license from dataset card metadata
  - [ ] **4.2.3** Handle 404 / private datasets → flag as WARNING
  - [ ] **4.2.4** Cache responses locally
- [ ] **4.3** Build well-known dataset license registry (hardcoded for common datasets)
  - [ ] **4.3.1** `common_crawl` → `CUSTOM_TOU` (scraped pages retain original copyright; no unified license)
  - [ ] **4.3.2** `laion/laion5B-*` → `CC-BY-4.0` metadata only (images retain original copyright)
  - [ ] **4.3.3** `EleutherAI/pile` → `MIT` assembly code (sub-datasets have individual licenses; Books3 removed)
  - [ ] **4.3.4** `wikipedia` → `CC-BY-SA-3.0` (ShareAlike: adaptations must use same license — flag for review)
  - [ ] **4.3.5** `imagenet-1k` → `CUSTOM_RESEARCH_ONLY` (non-commercial; commercial license required separately)
  - [ ] **4.3.6** `ms-coco` / `nlphuang/*coco*` → `CC-BY-4.0` annotations (flag: 99% of images had zero attribution provided)
  - [ ] **4.3.7** `bigcode/the-stack*` → `PER_FILE` (individual files retain original license including GPL/AGPL)
  - [ ] **4.3.8** `NVlabs/ffhq-dataset` → `CC-BY-NC-SA-4.0` (non-commercial only — CRITICAL if commercial use)
  - [ ] **4.3.9** `lmsys/chatbot_arena_conversations` → `CC-BY-NC-4.0` (non-commercial — CRITICAL if commercial use)
- [ ] **4.4** Implement license-specific violation logic for datasets
  - [ ] **4.4.1** `cc-by-nc*` detected → flag as HIGH: "Non-commercial only — commercial training is a clear violation"
  - [ ] **4.4.2** `cc-by-sa*` detected → flag as MEDIUM: "ShareAlike may require same license on model/outputs — legal review needed"
  - [ ] **4.4.3** `cc-by-nc-sa*` detected → flag as HIGH: both NC and SA restrictions apply
  - [ ] **4.4.4** Research-only datasets (ImageNet, VGGFace2) → flag as HIGH if commercial deployment indicators present
  - [ ] **4.4.5** Missing license → flag as WARNING: "No license found — manual review required before commercial use"

---

## Task 5: Policy Engine

> Allows configurable org-level allow/deny lists; produces severity-ranked findings

- [ ] **5.1** Design policy configuration schema (YAML file: `policy/compliance-policy.yml`)
  - [ ] **5.1.1** Define `allowed_licenses` list (e.g., `[apache-2.0, mit, bsd-3-clause, bsd-2-clause]`)
  - [ ] **5.1.2** Define `denied_licenses` list with severity (e.g., `agpl-3.0: CRITICAL`, `gpl-3.0: CRITICAL`)
  - [ ] **5.1.3** Define `review_required_licenses` list (e.g., `llama3: HIGH`, `openrail: MEDIUM`)
  - [ ] **5.1.4** Define `commercial_use: true/false` flag to toggle NC license violation detection
  - [ ] **5.1.5** Define `saas_deployment: true/false` flag to enable AGPL SaaS network clause enforcement
  - [ ] **5.1.6** Define `require_attribution_check: true/false` for Llama attribution scanning
- [ ] **5.2** Implement severity classification engine
  - [ ] **5.2.1** `CRITICAL` — GPL/AGPL in commercial distributed app, or AGPL in SaaS without source disclosure
  - [ ] **5.2.2** `HIGH` — Non-commercial dataset/model used commercially, Llama attribution missing, CC-BY-NC in commercial training
  - [ ] **5.2.3** `MEDIUM` — CC-BY-SA ShareAlike propagation risk, OpenRAIL behavioral restriction flagged, Llama distillation clause
  - [ ] **5.2.4** `WARNING` — Missing license metadata on package/model/dataset, ambiguous PyPI license string, unresolved dynamic reference
  - [ ] **5.2.5** `INFO` — Permissive license with attribution requirement, 700M MAU threshold informational
- [ ] **5.3** Build remediation recommendation engine
  - [ ] **5.3.1** `Unidecode (GPLv2+)` → "Replace `python-slugify` with `python-slugify[unidecode]` pinned to `text-unidecode`, or install `text-unidecode` directly (Artistic License)"
  - [ ] **5.3.2** `ultralytics AGPL-3.0` → "Purchase Ultralytics Enterprise License OR replace with RT-DETR (Apache-2.0)"
  - [ ] **5.3.3** `PyQt5/6 GPL-3.0` → "Replace with `PySide2`/`PySide6` (LGPL-2.1)"
  - [ ] **5.3.4** Missing Llama attribution → "Add 'Built with Meta Llama 3' to README and all user-facing documentation"
  - [ ] **5.3.5** CC-BY-NC dataset in commercial use → "Replace with permissively licensed alternative dataset"
  - [ ] **5.3.6** Generic AGPL → "Consult legal counsel; obtain commercial license or switch to Apache-2.0 alternative"
- [ ] **5.4** Implement CI/CD exit code logic
  - [ ] **5.4.1** Exit with code `1` (fail pipeline) if any CRITICAL findings exist
  - [ ] **5.4.2** Optionally exit `1` on HIGH findings (configurable via policy YAML)
  - [ ] **5.4.3** Always exit `0` (pass) for WARNING/INFO-only runs

---

## Task 6: CycloneDX ML-BOM Generator

> Produces the unified output artifact compatible with GitLab's security dashboard

- [ ] **6.1** Implement CycloneDX v1.5 BOM structure
  - [ ] **6.1.1** Set `specVersion: "1.5"` and `bomFormat: "CycloneDX"`
  - [ ] **6.1.2** Populate `metadata.component` with the scanned GitLab project name/version
  - [ ] **6.1.3** Add `metadata.timestamp` (ISO 8601)
  - [ ] **6.1.4** Add `metadata.tools` entry identifying this agent as the BOM generator
- [ ] **6.2** Map Python packages to CycloneDX `library` components
  - [ ] **6.2.1** Set `type: library` for each package
  - [ ] **6.2.2** Populate `purl` field: `pkg:pypi/{name}@{version}`
  - [ ] **6.2.3** Set `licenses[].expression` with SPDX license expression
  - [ ] **6.2.4** Add `evidence.licenses` showing source of license data (deps.dev, PyPI, hardcoded)
- [ ] **6.3** Map Hugging Face models to CycloneDX `machine-learning-model` components
  - [ ] **6.3.1** Set `type: machine-learning-model` for each model
  - [ ] **6.3.2** Populate `purl` field: `pkg:huggingface/{org}/{model}@{revision}`
  - [ ] **6.3.3** Set `licenses[].expression` or `licenses[].license.url` for custom licenses
  - [ ] **6.3.4** Add `externalReferences` with type `model-card` linking to `https://huggingface.co/{model_id}`
  - [ ] **6.3.5** Add use-restriction notes for OpenRAIL/Llama models in `description` field
- [ ] **6.4** Map datasets to CycloneDX `data` components
  - [ ] **6.4.1** Set `type: data` for each dataset
  - [ ] **6.4.2** Populate `purl` field: `pkg:huggingface/{dataset_id}`
  - [ ] **6.4.3** Set license and commercial eligibility in component metadata
  - [ ] **6.4.4** Add `externalReferences` linking to dataset page on Hugging Face Hub
- [ ] **6.5** Populate CycloneDX `vulnerabilities`-style compliance findings
  - [ ] **6.5.1** Encode each policy violation as a finding with: ID, severity, description, recommendation, affected component
  - [ ] **6.5.2** Map severity levels: CRITICAL → `critical`, HIGH → `high`, MEDIUM → `medium`, WARNING → `low`, INFO → `info`
- [ ] **6.6** Output the BOM
  - [ ] **6.6.1** Write `ml-sbom.json` to the repo root (or configurable output path)
  - [ ] **6.6.2** Also write human-readable `compliance-report.md` with findings grouped by severity
  - [ ] **6.6.3** Validate BOM against CycloneDX schema before writing (use `cyclonedx-py` validators)

---

## Task 7: GitLab CI/CD Integration

> The agent runs as a CI/CD job; findings appear in the security dashboard; critical findings block MRs

- [ ] **7.1** Write the CI/CD job definition (`.gitlab-ci.yml`)
  - [ ] **7.1.1** Define `ml-license-compliance` job in a `compliance` stage
  - [ ] **7.1.2** Use Python Docker image (`python:3.11-slim`) as the base
  - [ ] **7.1.3** Install scanner dependencies in the `before_script` section
  - [ ] **7.1.4** Run the scanner with `$CI_PROJECT_DIR` as the scan root
  - [ ] **7.1.5** Pass `$HF_TOKEN` and `$GITLAB_TOKEN` from CI/CD variables to the scanner
  - [ ] **7.1.6** Set `allow_failure: false` so CRITICAL findings fail the pipeline
- [ ] **7.2** Configure CycloneDX artifact upload
  - [ ] **7.2.1** Add `artifacts.reports.cyclonedx: ml-sbom.json` so GitLab parses the BOM into the security dashboard
  - [ ] **7.2.2** Add `artifacts.paths: [compliance-report.md, ml-sbom.json]` for download
  - [ ] **7.2.3** Set `artifacts.expire_in: 30 days`
- [ ] **7.3** Implement GitLab MR comment posting
  - [ ] **7.3.1** Detect if running in an MR context (`$CI_MERGE_REQUEST_IID` is set)
  - [ ] **7.3.2** Use GitLab API `POST /api/v4/projects/{id}/merge_requests/{iid}/notes` to post findings summary as MR comment
  - [ ] **7.3.3** Format comment as a collapsible Markdown summary with severity emoji (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, ⚠️ WARNING)
  - [ ] **7.3.4** Include remediation links in the comment
- [ ] **7.4** Configure Merge Request Approval Policy (optional but impressive)
  - [ ] **7.4.1** Create a `security-policy-project` if not existing
  - [ ] **7.4.2** Define an approval rule that requires 2 security approvers when `ml-license-compliance` job fails
  - [ ] **7.4.3** Link the policy to the demo project group
- [ ] **7.5** Configure Pipeline Execution Policy for org-wide enforcement (GitLab 17.9+)
  - [ ] **7.5.1** Create a `pipeline-execution-policy.yml` in the security policy project
  - [ ] **7.5.2** Use `inject_policy` strategy to inject `ml-license-compliance` job into all group project pipelines
  - [ ] **7.5.3** Document this as the "zero-touch org-wide deployment" in the demo

---

## Task 8: GitLab Duo Agent Configuration

> Required by hackathon rules: at least one custom public agent or public flow must be created

- [ ] **8.1** Create the GitLab Duo Agent YAML (from participant template)
  - [ ] **8.1.1** Copy `.agent.yml.template` to `agent/ml-compliance-agent.yml` (remove `.template` extension)
  - [ ] **8.1.2** Set agent `name: ML License Compliance Agent`
  - [ ] **8.1.3** Write agent `description`: what it does, who it's for, how to trigger it
  - [ ] **8.1.4** Define the agent `system_prompt` covering: scan scope, output format, violation categories, severity levels, remediation guidance
- [ ] **8.2** Define agent capabilities and tools in YAML
  - [ ] **8.2.1** Enable file reading tools to scan Python files in current project
  - [ ] **8.2.2** Enable web search / API call capability for Hugging Face Hub API
  - [ ] **8.2.3** Enable GitLab API tool for creating MR comments
  - [ ] **8.2.4** Enable artifact creation for CycloneDX BOM output
- [ ] **8.3** Write agent prompt instructions for each scan type
  - [ ] **8.3.1** Instructions for scanning `requirements.txt` and resolving transitive deps
  - [ ] **8.3.2** Instructions for extracting and validating HF model IDs from Python code
  - [ ] **8.3.3** Instructions for extracting and validating dataset IDs
  - [ ] **8.3.4** Instructions for applying the policy engine and categorizing findings
  - [ ] **8.3.5** Instructions for generating the compliance report and CycloneDX BOM
- [ ] **8.4** Commit the agent YAML and verify CI pipeline passes (validates schema)
  - [ ] **8.4.1** Push to main branch
  - [ ] **8.4.2** Check pipeline passes validation job
  - [ ] **8.4.3** Fix any schema validation errors reported by the pipeline
- [ ] **8.5** Create a git tag to publish the agent to the GitLab catalog
  - [ ] **8.5.1** Tag format: `v{major}.{minor}.{patch}` (e.g., `v1.0.0`) — GitLab catalog requires semver tags; confirm exact format in the Resources tab and the participant template pipeline output before tagging
  - [ ] **8.5.2** Verify agent appears in the GitLab Duo Chat agent selector
- [ ] **8.6** Test agent via GitLab Duo Chat sidebar
  - [ ] **8.6.1** Open a New GitLab Duo Chat and select the ML Compliance Agent
  - [ ] **8.6.2** Run a scan prompt against the demo repo
  - [ ] **8.6.3** Verify output matches expected compliance findings

---

## Task 9: Demo Repository Setup

> Plant real violations that the agent will catch — this is the core of the 3-minute demo

- [ ] **9.1** Create `demo-repo/` directory in the project with a realistic ML inference service
- [ ] **9.2** Demo 1 plant: "The Hidden GPL Trap" (30 seconds)
  - [ ] **9.2.1** Create `demo-repo/requirements.txt` including `python-slugify==8.0.1` (which transitively depends on `Unidecode` GPLv2+)
  - [ ] **9.2.2** Add other common ML packages to make requirements realistic: `torch`, `transformers`, `fastapi`, `uvicorn`
  - [ ] **9.2.3** Add `demo-repo/app.py` — a simple FastAPI inference server (makes it SaaS-context relevant)
  - [ ] **9.2.4** Do NOT add the `text-unidecode` fix yet (scanner should catch and recommend it)
- [ ] **9.3** Demo 2 plant: "The LLaMA Triple Violation" (90 seconds)
  - [ ] **9.3.1** Create `demo-repo/inference.py` with `AutoModelForCausalLM.from_pretrained("meta-llama/Meta-Llama-3-8B-Instruct")`
  - [ ] **9.3.2** Create `demo-repo/train_data.py` with `load_dataset("lmsys/chatbot_arena_conversations")` (CC-BY-NC-4.0)
  - [ ] **9.3.3** Create `demo-repo/distill.py` — a script that uses outputs of LLaMA to train a smaller non-Llama model (anti-competition clause violation)
  - [ ] **9.3.4** Do NOT add "Built with Meta Llama 3" attribution to the README (attribution violation)
  - [ ] **9.3.5** Verify three distinct violations exist: missing attribution, distillation clause, CC-BY-NC dataset
- [ ] **9.4** Demo 3 plant: "The AGPL SaaS Bomb" (60 seconds)
  - [ ] **9.4.1** Add `ultralytics==8.0.200` to `demo-repo/requirements.txt`
  - [ ] **9.4.2** Create `demo-repo/detect.py` — a FastAPI endpoint using YOLOv8 for object detection
  - [ ] **9.4.3** Add `demo-repo/Dockerfile` — containerized deployment (confirms SaaS deployment context)
  - [ ] **9.4.4** Verify: ultralytics (AGPL-3.0) + FastAPI + Dockerfile = CRITICAL AGPL SaaS violation
- [ ] **9.5** Verify all violations are caught by running the scanner manually before the demo
  - [ ] **9.5.1** Run `python scanner/main.py --path demo-repo/` and confirm all 5+ violations appear
  - [ ] **9.5.2** Verify severity classification is correct for each finding
  - [ ] **9.5.3** Verify remediation recommendations are present for each finding
  - [ ] **9.5.4** Verify CycloneDX `ml-sbom.json` is generated with all components

---

## Task 10: Anthropic / Claude Integration (Bonus Prize Track)

> Qualifies for "Most Impactful on GitLab & Anthropic" prize ($10,000 grand / $3,500 runner-up)

- [ ] **10.1** Integrate Claude via GitLab Duo Agent Platform (no personal API key needed — hackathon group provides access)
  - [ ] **10.1.1** Use Claude through the GitLab Duo Agent YAML (defined in Task 8) — invoke Claude as a tool call inside the agent, not via direct `anthropic` SDK in CI scripts
  - [ ] **10.1.2** Call Claude to interpret ambiguous license text (e.g., parse raw LICENSE file text and extract license type)
  - [ ] **10.1.3** Call Claude to generate plain-English risk summaries for non-legal engineers
  - [ ] **10.1.4** Call Claude to generate context-aware remediation advice based on the specific project type
- [ ] **10.2** Use Claude for OpenRAIL use-restriction analysis
  - [ ] **10.2.1** Send the project description + OpenRAIL prohibited use cases to Claude
  - [ ] **10.2.2** Ask Claude to assess whether the project's apparent purpose (from README/code) might conflict with OpenRAIL restrictions
  - [ ] **10.2.3** Output as a "MEDIUM — Human Review Suggested" finding with Claude's reasoning
- [ ] **10.3** Use Claude to summarize entire compliance report
  - [ ] **10.3.1** Feed all findings to Claude and ask for an executive summary for a non-technical audience
  - [ ] **10.3.2** Include the executive summary at the top of `compliance-report.md`
- [ ] **10.4** Ensure Claude is being run through GitLab (required for Anthropic prize eligibility)
  - [ ] **10.4.1** Claude must be invoked via the GitLab Duo Agent Platform (not a raw Anthropic API key in CI scripts) — the hackathon group provides the model access; the agent YAML is the execution context
  - [ ] **10.4.2** Document this in the project README as "Powered by Anthropic Claude via GitLab Duo Agent Platform"

---

## Task 11: Testing

- [ ] **11.1** Unit tests for Python package scanner
  - [ ] **11.1.1** Test `requirements.txt` parser with various pin formats
  - [ ] **11.1.2** Test deps.dev API response parsing (mock API response)
  - [ ] **11.1.3** Test GPL transitive dependency detection (python-slugify → Unidecode)
  - [ ] **11.1.4** Test AGPL + SaaS indicator detection (ultralytics + fastapi)
- [ ] **11.2** Unit tests for model scanner
  - [ ] **11.2.1** Test regex extraction of `from_pretrained("org/model")` patterns
  - [ ] **11.2.2** Test detection of dynamic references (should flag as UNRESOLVED, not silently skip)
  - [ ] **11.2.3** Test HF API response parsing (mock response for `meta-llama/Meta-Llama-3-8B-Instruct`)
  - [ ] **11.2.4** Test custom license taxonomy mapping (llama3 → CUSTOM_RESTRICTED)
- [ ] **11.3** Unit tests for dataset scanner
  - [ ] **11.3.1** Test `load_dataset()` regex with single-arg and two-arg forms
  - [ ] **11.3.2** Test CC-BY-NC detection and HIGH severity classification
  - [ ] **11.3.3** Test well-known dataset registry lookup (FFHQ, chatbot_arena_conversations)
- [ ] **11.4** Integration test: end-to-end scan of `demo-repo/`
  - [ ] **11.4.1** Run full scanner on `demo-repo/` and assert exactly the expected violations are found
  - [ ] **11.4.2** Assert `ml-sbom.json` is valid CycloneDX v1.5 JSON
  - [ ] **11.4.3** Assert exit code `1` due to CRITICAL findings
  - [ ] **11.4.4** Assert MR comment would be generated (mock GitLab API call)
  - [ ] **11.4.5** ⚠️ Tests must be read-only against `demo-repo/` — never auto-fix violations during test runs; `demo-repo/` must stay intentionally broken for the demo

---

## Task 12: Documentation & README

- [ ] **12.1** Write `README.md` with:
  - [ ] **12.1.1** One-sentence description: what the agent does and why it's unique
  - [ ] **12.1.2** The compliance gap it fills (vs FOSSA, Snyk, Black Duck table)
  - [ ] **12.1.3** Installation and usage instructions (local + CI/CD)
  - [ ] **12.1.4** Policy configuration guide (`compliance-policy.yml` schema)
  - [ ] **12.1.5** Example output / findings for each demo scenario
  - [ ] **12.1.6** Architecture diagram (simple ASCII or embedded image)
  - [ ] **12.1.7** "Powered by Anthropic Claude via GitLab CI/CD" badge/note for Anthropic prize track
- [ ] **12.2** Add open source license to the repository
  - [ ] **12.2.1** Choose Apache-2.0 (recommended for GitLab ecosystem compatibility)
  - [ ] **12.2.2** Add `LICENSE` file to repo root
  - [ ] **12.2.3** Verify license is auto-detected and visible in the GitLab Project Information section (required for submission)
- [ ] **12.3** Write agent usage guide (how to invoke from GitLab Duo Chat)
- [ ] **12.4** Write CI/CD integration guide (how to add the job to an existing project)

---

## Task 13: Demo Video Production (3 minutes max)

> Required for submission. Upload to YouTube or Vimeo (public).

- [ ] **13.1** Script the 3-minute demo (use this exact flow):
  - [ ] **13.1.1** 0:00–0:10 — Hook: "65% of Hugging Face models have no license. No tool checks model + dataset + package licenses together. Until now."
  - [ ] **13.1.2** 0:10–0:40 — Demo 1: Show `requirements.txt` with `python-slugify`. Run scanner. Show CRITICAL: Unidecode (GPLv2+) flagged, dependency chain visible, `text-unidecode` recommended.
  - [ ] **13.1.3** 0:40–2:10 — Demo 2: Show `inference.py` + `train_data.py` + `distill.py`. Run scanner. Show 3 violations: missing Llama attribution, distillation clause, CC-BY-NC dataset. Show specific license clause references in output.
  - [ ] **13.1.4** 2:10–2:40 — Show the CycloneDX ML-BOM appearing in GitLab's security dashboard. Show MR blocked with CRITICAL findings in the merge request comment.
  - [ ] **13.1.5** 2:40–3:00 — Closing split-screen: "Before: 3 tools, manual review. After: one CI/CD job, zero missed violations."
- [ ] **13.2** Record the demo
  - [ ] **13.2.1** Use a screen recorder (QuickTime on Mac, or OBS)
  - [ ] **13.2.2** Record at 1080p minimum
  - [ ] **13.2.3** Narrate live or add voiceover
  - [ ] **13.2.4** Keep total runtime under 3:00 (judges will not watch beyond 3 minutes)
- [ ] **13.3** Edit and upload
  - [ ] **13.3.1** Light editing: trim dead air, add text callouts for key findings
  - [ ] **13.3.2** Upload to YouTube as Public (not Unlisted — judges must be able to watch)
  - [ ] **13.3.3** Set a descriptive title: "ML License Compliance Agent — GitLab AI Hackathon Demo"
  - [ ] **13.3.4** Save the YouTube URL for Devpost submission

---

## Task 14: Hackathon Submission (Due March 25, 2026 @ 11:00am PDT)

- [ ] **14.1** Verify all submission requirements are met before submitting
  - [ ] **14.1.1** GitLab repo URL is public and in the AI Hackathon group
  - [ ] **14.1.2** All source code, assets, and instructions are in the repo
  - [ ] **14.1.3** License is Apache-2.0, is visible in the Project Information section on the GitLab project page
  - [ ] **14.1.4** At least one custom public agent OR public flow is created and tagged/published to the catalog
  - [ ] **14.1.5** Demo video is uploaded to YouTube as Public and is under 3 minutes
  - [ ] **14.1.6** CI pipeline passes (agent YAML schema validates)
- [ ] **14.2** Write Devpost project text description
  - [ ] **14.2.1** Open with the problem: the compliance gap (no tool checks code + models + datasets)
  - [ ] **14.2.2** Describe the three violation types caught (GPL trap, Llama triple, AGPL SaaS bomb)
  - [ ] **14.2.3** Explain CycloneDX ML-BOM output and GitLab security dashboard integration
  - [ ] **14.2.4** Mention EU AI Act enforcement (Aug 2025) for regulatory urgency
  - [ ] **14.2.5** Note Anthropic/Claude integration for Anthropic prize track eligibility
  - [ ] **14.2.6** Note that this is first-to-market: no other tool does unified ML compliance scanning in CI/CD
- [ ] **14.3** Submit on Devpost
  - [ ] **14.3.1** Go to the hackathon page on Devpost and click "Submit Project"
  - [ ] **14.3.2** Paste GitLab repo URL
  - [ ] **14.3.3** Paste YouTube demo video URL
  - [ ] **14.3.4** Paste project text description
  - [ ] **14.3.5** Double-check all fields are filled before final submission
  - [ ] **14.3.6** Screenshot submission confirmation

---

## Quick Reference: APIs & Commands

### Hugging Face Hub API
```
GET https://huggingface.co/api/models/{model_id}?cardData=true
GET https://huggingface.co/api/datasets/{dataset_id}
```

### deps.dev API (PyPI license lookup)
```
GET https://api.deps.dev/v3/systems/pypi/packages/{name}/versions/{version}
```

### GitLab API (org scan)
```
GET /api/v4/groups/{group_id}/projects?include_subgroups=true&per_page=100
GET /api/v4/projects/{project_id}/repository/tree?recursive=true&per_page=100
GET /api/v4/projects/{project_id}/repository/files/{encoded_path}/raw?ref=main
POST /api/v4/projects/{id}/merge_requests/{iid}/notes
```

### Regex patterns (model/dataset extraction)
```python
PATTERNS = [
    r'''\.from_pretrained\(\s*["']([a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+)["']''',
    r'''pipeline\([^)]*model\s*=\s*["']([a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+)["']''',
    r'''SentenceTransformer\(\s*["']([a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+)["']''',
    r'''load_dataset\(\s*["']([a-zA-Z0-9_-]+(?:/[a-zA-Z0-9._-]+)?)["']''',
]
```

### Severity levels
| Severity | Trigger | Pipeline action |
|----------|---------|----------------|
| CRITICAL | GPL/AGPL in distributed/SaaS app | Fail pipeline |
| HIGH | NC data commercially used, missing Llama attribution | Fail pipeline (configurable) |
| MEDIUM | CC-BY-SA propagation risk, OpenRAIL flags | Warn only |
| WARNING | Missing license metadata, unresolved references | Warn only |
| INFO | Attribution-only requirements, MAU thresholds | Informational |
