# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.6] - 2026-06-05

### Fixed
- **Vertex AI Temperature Deprecation Crash:**
  - Resolved an application crash (`litellm.BadRequestError: Vertex_aiException BadRequestError`) occurring when Vertex AI models reject the `temperature` parameter. Implemented dynamic exception interception across the `Gemini` and `LiteLlm` ADK client bridges that automatically catches this specific error and retries the request without `temperature`, rather than relying on hardcoded model name checks.

### Added
- **Strict Model Availability Enforcement:**
  - Removed silent fallbacks when a requested model is unavailable. The application will now strictly halt execution and fail fast, ensuring users are explicitly aware of model provisioning or subscription issues instead of unexpectedly degrading to a default model.

### Changed
- **Default Models Updated:**
  - Upgraded the baseline default AI models to `gemini-3.1-pro` and `gemini-3.5-flash` across the configuration.
- **Cost Catalogs Updated:**
  - Updated the dynamic cost metric catalogs in `default_prices.json` to accurately reflect the token pricing for `gemini-3.1-pro` and `gemini-3.5-flash`.

## [1.5] - 2026-05-29

### Added
- **Third-Party Vertex AI Model Support (Anthropic Claude):**
  - Fully resolved execution issues when running non-Gemini models (like Anthropic Claude Opus) via GCP Vertex AI through the ADK `LiteLlm` bridge.
  - Implemented a dynamic wrapper class (`StrippedLiteLlm`) to automatically intercept and strip unsupported native arguments (such as `temperature=0.0` inside the generation config) that caused `BadRequestError` crashes on thinking models.
  - Corrected Vertex AI location routing by explicitly setting `VERTEXAI_LOCATION` and `VERTEXAI_PROJECT` environment variables for the ADK LLM client, allowing global models (like Claude) to bypass the default `us-central1` routing constraint.
  - Hardened token usage parsing inside the `calculate_session_token_costs` telemetry function to correctly extract `prompt_tokens` and `completion_tokens` (from LiteLLM/OpenAI-formatted payloads) alongside the native Gemini `prompt_token_count` metrics.
- **Dynamic Terminal CVE Extraction:**
  - Upgraded the CLI output engine to dynamically regex-extract CVE references from the validation reasoning and sandbox evidence payloads. Terminal alerts now prominently feature CVEs inline (e.g., `🔥 Vulnerability Validated: CVE-2026-48710 (gemini.broken-authz) inside main.py`).
- **Resilient AI Stringified Output Parsing:**
  - Fixed an edge case where third-party LLMs returned the `findings` state block as stringified JSON (`"[{...}]"`) instead of raw JSON arrays. The results processor now intercepts, un-stringifies, and parses these blocks natively to guarantee finding tables aren't silently skipped.

### Changed
- **Model-Agnostic Terminology:**
  - Renamed "Gemini-driven playbooks" to "AI-driven playbooks" across the codebase UI, CLI descriptions, agent prompts, and documentation. This ensures model agnosticism when running the scanner with third-party models like Claude Opus.
- **Explicit Validation Types (Static vs Dynamic):**
  - Updated the Validation Agent to explicitly tag findings with a `validation_type` of either `STATIC` or `DYNAMIC`.
  - The final Markdown report tables and detailed finding titles now explicitly reflect this distinction (e.g., `Validated [STATIC]`).
  - Terminal output dynamically extracts and prints this status inline (e.g., `🔥 Vulnerability Validated (STATIC):`).

### Fixed
- **SQLite Findings Database Parsing:**
  - Correctly resolved a regression in the results compiler (`app/cli/results.py`) by falling back to `validated_findings`, `triaged_findings`, and `scanner_findings` keys in the SQLite session state database when remediation outputs are absent. This prevents the CLI from displaying a false "Audit Clean" banner when findings are present but remediation was not executed.
- **CVE Telemetry Misattribution:**
  - Added programmatic JSON object brace-matching extraction to `app/cli/main.py` to map CVEs specifically to their corresponding parent finding rules during real-time terminal logging, preventing the first parsed CVE from being incorrectly assigned to all subsequent rules printed in the same stream chunk.
- **Model Routing Test Assertions:**
  - Updated model routing unit test assertions in `tests/unit/test_gcs.py` to check for the wrapper class name `StrippedLiteLlm` rather than the underlying `LiteLlm` class, fixing test collection and execution passes.
- **PyInstaller Standalone Binary Compilation:**
  - Packaged all necessary `litellm` pricing catalogs and registry configuration files using `collect_data_files('litellm')` to prevent runtime dictionary file path exceptions.
  - Fully resolved the `Unknown encoding cl100k_base` bootstrapper crash by using `collect_all('tiktoken_ext')` and adding `tiktoken_ext` and `tiktoken_ext.openai_public` namespace packages to PyInstaller's `hiddenimports` list.
  - Disabled UPX compression (`upx=False`) in the build spec file to prevent dynamic module zip archive and Mach-O header corruption (`zlib.error: Error -3 while decompressing data: incorrect header check`) on Apple Silicon macOS.
- **PyInstaller Build Configuration:**
  - Configured `.gitignore` to explicitly allow `!rh.spec` while ignoring `test_*.py` files, ensuring the macOS binary build manifest remains safely tracked in version control.

## [1.4] - 2026-05-25

### Added
- **Multi-threaded Parallel Chunk Processing (Speed):**
  - Integrated `ThreadPoolExecutor` to process chunked scan batches concurrently, gated by a new `--parallel` CLI argument.
  - Implemented a thread-safe unified dynamic console dashboard using a single Rich `Live` progress panel to display active batch phases, active tools, elapsed times, and validated findings across multiple threads.
- **Expanded Tree-Sitter AST Support:**
  - Added support for 8 additional language parsers: Rust (`tree-sitter-rust`), Ruby (`tree-sitter-ruby`), PHP (`tree-sitter-php`), C# (`tree-sitter-c-sharp`), TypeScript (`tree-sitter-typescript`), HTML (`tree-sitter-html`), CSS (`tree-sitter-css`), and JSON (`tree-sitter-json`).
  - Wrapped imports in resilient `try...except ImportError` blocks to ensure dynamic import safety and prevent tool failures on systems with missing bindings.
  - Implemented extensive unit tests for all 8 new languages, bringing total unit test count to 39.
- **Graceful Ctrl+C Process Interruption:**
  - Implemented immediate `KeyboardInterrupt` handling for the `ThreadPoolExecutor` parallel execution path. Pressing Ctrl+C now triggers a non-blocking `executor.shutdown(wait=False, cancel_futures=True)` and calls `os._exit(1)` to terminate all threads and the entire process tree instantly.
  - Added a top-level `KeyboardInterrupt` handler in `entry_point()` that cleans up the background ADK server and exits immediately, preventing the CLI from hanging on thread joins or blocked socket reads.
- **Remediation Agent Retry Ceiling:**
  - Added a strict maximum cap of **2 patch revision attempts** to `REMEDIATION_INSTRUCTION` in `app/agent.py`. If post-patch sandbox verification fails after the second revision, the agent records `patch_verified: false`, documents the failure in `validation_evidence`, and proceeds to the next finding. This prevents indefinite loops caused by Vertex AI rate-limiting backoffs (429 errors with 180s exponential retries).
- **FastAPI /healthz Health Probe Endpoint:**
  - Added a GET `/healthz` endpoint in `app/fast_api_app.py` mapping to `health_check` as a standard URL alias for environment/readiness health probes.
- **Enhanced Standalone Dockerfile:**
  - Configured `Dockerfile` to install and pack all core static analysis tools (`semgrep`, `bandit`, `trivy`, `gitleaks`) internally, and added a curl-based container HTTP `HEALTHCHECK` pointing to `/healthz` for deployment validation.
- **Google Cloud Build CI/CD Pipeline:**
  - Created `cloudbuild.yaml` in the repository root to automate the end-to-end integration lifecycle: running unit tests, building the production image, tagging with commit SHA and pushing to Artifact Registry, and deploying to Cloud Run.
- **Terraform GCP Infrastructure Module:**
  - Authored a fully modular IaC setup under `deploy/` (`main.tf`, `variables.tf`, `outputs.tf`, `README.md`) to provision Reference Harness in GCP with a dedicated Service Account, object storage buckets, uniform permissions, and secure Cloud Run service scaling.
- **Visual Deployment Architecture:**
  - Generated and embedded a modern, professional GCP deployment flow diagram directly in `DEPLOYMENT.md` to improve architectural visibility.

### Fixed
- **Dashboard Elapsed Timer Accuracy:**
  - Fixed the parallel progress dashboard in `app/cli/main.py` to display the **total batch execution time** (measured from batch spawn) instead of the **current phase duration**. Previously, completed batches displayed misleadingly short times (e.g., `3.8s`) because the timer only measured the final Report phase. Now all batches show their true cumulative execution duration.
- **`UnboundLocalError: cannot access local variable 'os'`:**
  - Removed redundant `import os` statements placed inside `except KeyboardInterrupt` handler blocks within `main()` and `entry_point()`. Python's scoping rules treated these as local variable declarations, shadowing the top-level `import os` and causing `os.path.exists()` calls at the start of `main()` to fail with an `UnboundLocalError`.
- **GCS Bucket Verification Print Order:**
  - Relocated the GCS bucket existence check to print **after** the ASCII logo banner and target path info panel, but **before** Vertex AI model subscription verification. This ensures a clean, logical console output sequence matching the user's expected flow.

## [1.3] - 2026-05-24

### Added
- **Modular CLI Refactoring:** Split the massive 1443-line `scan.py` file into clean, modular submodules under `app/cli/` (`bootstrap.py`, `models.py`, `costs.py`, `server.py`, `streaming.py`, `results.py`, `main.py`). `scan.py` is now a thin wrapper.
- **Support for SARIF/Markdown Output Formats:** Added the `--output-format` flag, supporting `markdown` (default), `sarif`, or `both` formats. Integrated the `write_sarif_report` function to generate valid SARIF v2.1.0 JSON reports.
- **Scanner Execution Deduplication:** Implemented memory-based cache lookup in all static scanners (`run_semgrep`, `run_trivy`, `run_gitleaks`, `run_bandit`), ensuring scans execute exactly once per codebase root and deduplicating work across chunked batches.
- **Hardcoded Relative Paths Cleanup:** Replaced all hardcoded relative paths that resolve relative to CWD (like `app/app_utils/...` or `./.adk/sandbox`) with package-relative resolution using `Path(__file__)` or system temporary directories via `tempfile.mkdtemp()`.
- **Sandbox Security Hardening:** Hardened the Docker container execution sandbox with memory (256MB), CPU (0.5), PID limits (50), read-only rootfs, and read-write tmpfs. Hardened the macOS native sandboxing profile to restrict file writes strictly to the validation temporary directory.
- **Code Quality Improvements:** Added logger configurations in CLI main loop, replacing silent exception swallowing with diagnostic logging. Created `app/app_utils/__init__.py` for correct package recognition.

## [1.2] - 2026-05-22

### Added
- **Zero-Day Polymorphic Stack & Decoupled Registry (SOTA Release 3.0.0 Milestone!):**
  * **Polymorphic Stack Auto-Discovery:** Upgraded `bootstrap_codebase_signatures` in [scan.py](./scan.py#L146) and `map_boundaries` in [tools.py](./app/tools.py#L917) to dynamically discover, create, and map **any codebase stacks (web, systems, iac, mobile, web3, embedded) concurrently** without hardcoded category constraints.
  * **Autogenous Self-Learning Playbook Walks:** Synthesizes and appends newly fanned-out signatures (e.g., Elixir Phoenix controller macros, AWS Lambda handlers, and Jsonnet gateway files) permanently back to disk on `framework_signatures.json`, automatically sorting and deduplicating.
  * **Extension-Based Heuristics Fallback:** Sweeps target directories in microseconds to infer stack profiles from unique file extensions if configuration manifests are completely absent, maintaining the AI learning loop.
  * **Decoupled Pricing & Resilient Fallbacks:** Wiped all hardcoded pricing rates and default models from Python, loading them dynamically from `default_prices.json`. Added strict schema and file integrity gates with descriptive warnings.
  * **E2E Resilient & Persistent Tool Telemetry Spinner:** Intercepts Server-Sent Events (SSE) streams using a robust regex scanner, translating raw ADK function calls to human-friendly descriptive progress actions. Restructured the spinner to keep displaying the last invoked action persistently instead of clearing it instantly. Added **Resilient Verbal Telemetry Extraction** to recursively capture and display active files/playbooks context logs (e.g. *"Auditing ec2_iam_roles.libsonnet for permissive access..."*) directly from the agent's streamed text chunks, guaranteeing stable, informative console feedback even under restricted proxy streams.
  * **Dynamic Google AI Studio API Key Auth & Self-Healing Fallback:** Integrated `GEMINI_API_KEY` support, dynamically instantiating clients with `vertexai=False` to completely isolate GCP ADC hooks and bypass Vertex AI billing paths on API Key runs. Engineered a proactive validation check at startup: if the key is invalid or inactive, the system automatically pops the key, prints a warning on the screen, and cascades cleanly and transparently back to Google Cloud Vertex AI (ADC authentication).
  * **10-Minute HTTP Socket Client Timeouts:** Configured robust `http_options={"timeout": 600.0}` parameters on high-end, long-running client sweeps to completely eliminate socket read timeouts during large codebase audits. Removed custom timeouts from Bootstrapper and Reporting clients to prevent corporate network proxies (Airlock) from intercepting and blocking light requests with invalid 1s deadline RPC errors.
  * **Dynamic Multi-Stack Telemetry Labeling:** Upgraded the bootstrapper to list all fanned-out stacks concurrently on the terminal (e.g. `✓ Codebase dynamically classified across multiple stacks: IAC, WEB!`).
  * **Pruned active boundaries diagnostics log:** Logs the exact compiled files fanned across chunked batches cleanly to `app/.adk/boundary_files.log` for full diagnostics transparency.

## [1.1] - 2026-05-21

### Added
- **Segmented File Batching & Parallel Execution Core:**
  - Re-engineered Reference Harness's discovery and scanning pipeline to natively support Segmented File Batching. Partitions large harvested boundary files list into context-safe chunks of 25 files each, running sequential, cached Gemini passes.
  - Lifted Uvicorn server boot-up and session allocation completely outside the batch loop, instantiating a single, unified session ID once for the entire run. All chunked batches execute under this identical `session_id` to consolidate findings cleanly.
  - Consolidated SQLite database session state findings fanned out across all chunked batches, ensuring comprehensive coverage with zero omissions.
  - Sorted the mapped codebase boundary files list alphabetically before chunking to eliminate filesystem-level non-deterministic directory walk orders.
- **Port 18080 & Background Uvicorn Resiliency:**
  - Redirected Uvicorn's stdout/stderr outputs directly to a temporary filesystem log file (`app/.adk/uvicorn_boot.log`) to eliminate Python subprocess pipe deadlocks and memory locks.
  - Added a socket-based TCP handshake readiness check after launch to guarantee the server is fully booted and accepting requests.
  - Integrated a programmatic port-18080 process killer using macOS `lsof` with `-n` and `-P` flags and `-sTCP:LISTEN` filtering to force-terminate stale background Uvicorn processes without network hang delay.
  - Engineered a high-fidelity, 3-attempt retry loop on Uvicorn server startup with a 2.0-second socket release delay to handle macOS `TIME_WAIT` socket reuse locks.
  - Omitted external `agents-cli --stop-server` calls and switched to direct Python-based `force_kill_port` utility to bypass corporate network proxies (`gpkg` / `Corp Airlock`) warnings.
- **Static Scanners & Rule optimization:**
  - Upgraded Semgrep configuration from `--config=auto` to Semgrep's built-in local ruleset `--config=p/default` and added `--no-git-ignore` to unlock 100% offline-safe capability.
  - Expanded the out-of-the-box playbook dictionary to include 8 comprehensive security playbooks for C/C++ compiled codebases (Stack/Heap overflows, Use-After-Free, TOCTOU, JWT bypass, SSRF).
- **Agent Capabilities & Sandbox Upgrades:**
  - Equipped the `remediation_agent` with `grep_code`, `find_references`, `list_dir`, and `map_boundaries` tools to resolve agent validation execution crashes during patch diff synthesis.
  - Added strict dynamic AST mocking guidelines directing the Validation Agent to dynamically generate mock stubs for database/network libraries (Postgres, MySQL, Redis, Mongoose).
  - Expanded Codebase Boundary Compiler to dynamically map and harvest Infrastructure-as-Code (IaC) files (Terraform `.tf`, AWS CDK, Serverless).
- **DX, Telemetry & Real-Time Dashboards:**
  - Upgraded the SSE streaming terminal CLI loops to track and parse active sub-agent tool executions (e.g. Semgrep, Sandbox) and display them dynamically.
  - Integrated a console "Fire Interceptor" that prints a real-time notification (`🔥 Vulnerability Validated: <rule_id> inside <file_name>`) as soon as a vulnerability is successfully validated in the sandbox.
  - Integrated a cyan-bordered console panel that reads the audit report and prints the AI-generated Executive Summary, along with a clickable `file:///` link to the report.
  - Rendered a color-coded findings table using Rich summarizing discovered vulnerabilities.
  - Added dynamic CLI flags (`--pro-model`, `--flash-model`, `--location`, `--chunk-size`) to support non-interactive execution for CI/CD runs.
  - Added dynamic model selection checking that runs a 1-token dry-run validation probe to detect billing/permission errors before starting a scan.
  - Upgraded cost calculations to dynamically query pricing schedules from LiteLLM's registry or load from `default_prices.json`.
- **Bug Fixes & General Stability:**
  - Resolved SQLite session consolidate query column name mismatch (filter on table primary key `id` instead of `session_id`).
  - Switched baseline models to universally available `gemini-2.5-pro` and `gemini-2.5-flash` to prevent regional deployment errors.
  - Fixed python local variable scope crash inside results compiler by moving the report folder list binding outside conditional blocks.
  - Fixed EventSource stream connection context management bug that closed connections prematurely.

## [1.0] - 2026-05-20

### Added
- **Autogenous Git Patching & Consent Choice Board (Phase D):**
  - Coded the `remediation_agent` utilizing Gemini to analyze validated vulnerabilities and synthesize safe, Unified Git Diff patches.
  - Implemented an interactive choice board displaying code modifications in color-coded Git-style Diff console layouts.
  - Added checkbox developer consent gates and a three-tiered action board: (1) Submit Pull Request with One-Click Comparison Link, (2) Apply locally as a new feature branch, or (3) Discard.
  - Coded an automated post-patch dynamic verification scan run to verify applied fixes instantly.
  - Integrated `-t` (silent) and `-N` (forward-only) flags into the `patch` command runner to dynamically suppress interactive prompts under background executions.
  - Added `test_apply_patch_unified_diff` unit tests validating Unified Diff applications.
- **Multi-Mode Secure Sandbox Engine (Phase C):**
  - Authored a secure, isolated `sandbox.py` executing untrusted exploit validation scripts inside container/native runtimes.
  - Configured four cascading execution isolation levels: `docker` (network-disabled Alpine container runtimes), `native` (macOS `sandbox-exec`/Linux `firejail` constraints), `local` (host subprocess with terminal warning blocks), and `static` (read-only triage dry-run).
  - Created standard security validation playbooks (covering Command Injection, SQLi, SSRF, XSS, CSRF, Authz, and IDOR) to guide the fuzzer scripts.
  - Added Bash/Shell scripting support in validation sandboxes, verified with unit tests (`test_execute_in_sandbox_local_bash`, `test_execute_in_sandbox_auto_mock_mongoose`).
- **AST Querying & Scanner Normalization (Phase B):**
  - Implemented AST-querying `query_ast` in `app/tools.py` using `tree-sitter` S-expression parsing API for Python and Javascript, verified with unit tests.
  - Standardized Semgrep, Trivy, Bandit, and Gitleaks scan outputs into normalized OASIS SARIF v2.1.0 JSON formats, decoupling prompt maintenance from static scanner additions.
  - Added symbol and caller tracing tool `find_references` to dynamically search whole-word identifiers and construct grounded exploit chains.
  - Integrated Java benchmarking codebase (`eval-fixtures/benchmark-java/`) and custom rubrics (`eval_config.json`) to measure multi-language generalization.
- **ROI Pricing Calculations & DX Polish:**
  - Coded dynamic cost calculation metrics that query LiteLLM's pricing catalog or fallback to `default_prices.json` with support for custom discount rates (`REFERENCE_HARNESS_ENTERPRISE_DISCOUNT`).
  - Integrated ASCII art banners, Rich console status spinners, animated stopwatches, and cyan-bordered console panels displaying reports executive summaries and clickable file links.
  - Externalized third-party URLs to `default_prices.json` configurations to decouple dependencies.
- **Scaffold & Containerization (Phase A):**
  - Authored standard `Dockerfile` preparing Reference Harness for Cloud Run / GKE hosting.
  - Upgraded legacy project structures to the modern scaffold standard (generating `agents-cli-manifest.yaml`).
  - Configured the `triage_agent` to run under deterministic configurations (temperature=0.0) to ensure reproducible false-positive filtering.
  - Fixed Starlette double-slash routing issues and mock server app alignment bugs.
