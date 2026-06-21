# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ruff: noqa
"""VulnCatcher root agent: SequentialAgent pipeline over discovery → triage → validation → report."""

import os

try:
    import litellm

    litellm.suppress_debug_info = True
except Exception:
    pass

import google.auth
from google.adk.agents import Agent, ParallelAgent, SequentialAgent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from .plugins import ScannerAllowlistPlugin
from .sandbox import execute_in_sandbox
from .tools import (
    _build_skill_index,
    detect_languages,
    find_references,
    grep_code,
    list_dir,
    load_skill,
    map_boundaries,
    query_ast,
    read_code_window,
    run_bandit,
    run_gitleaks,
    run_semgrep,
    run_trivy,
    write_report,
)

# Resolve the GCP project ID dynamically from environment variables or standard ADC defaults!
project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get(
    "VULNCATCHER_PROJECT"
)
if not project_id:
    try:
        _, auth_project = google.auth.default()
        project_id = auth_project
    except Exception:
        pass
if not project_id:
    raise ValueError(
        "Project ID could not be automatically determined. Please set GOOGLE_CLOUD_PROJECT explicitly!"
    )

os.environ["GOOGLE_CLOUD_PROJECT"] = project_id
os.environ["GOOGLE_CLOUD_LOCATION"] = "global"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"
# LiteLLM / ADK LiteLlm reads these specific env vars for Vertex AI routing
os.environ["VERTEXAI_PROJECT"] = project_id
os.environ["VERTEXAI_LOCATION"] = os.environ.get(
    "GOOGLE_CLOUD_LOCATION", "global"
)


def _get_stripped_litellm():
    from google.adk.models import LiteLlm

    class StrippedLiteLlm(LiteLlm):
        async def generate_content_async(self, llm_request, stream=False):
            try:
                async for event in super().generate_content_async(
                    llm_request, stream
                ):
                    yield event
            except Exception as exc:
                if (
                    "temperature" in str(exc).lower()
                    and llm_request
                    and llm_request.config
                    and hasattr(llm_request.config, "temperature")
                    and llm_request.config.temperature is not None
                ):
                    llm_request.config.temperature = None
                    async for event in super().generate_content_async(
                        llm_request, stream
                    ):
                        yield event
                else:
                    raise

    return StrippedLiteLlm


def _get_stripped_gemini():
    from google.adk.models import Gemini

    class StrippedGemini(Gemini):
        async def generate_content_async(self, llm_request, stream=False):
            try:
                async for event in super().generate_content_async(
                    llm_request, stream
                ):
                    yield event
            except Exception as exc:
                if (
                    "temperature" in str(exc).lower()
                    and llm_request
                    and llm_request.config
                    and hasattr(llm_request.config, "temperature")
                    and llm_request.config.temperature is not None
                ):
                    llm_request.config.temperature = None
                    async for event in super().generate_content_async(
                        llm_request, stream
                    ):
                        yield event
                else:
                    raise

    return StrippedGemini


def _model():
    model_name = os.environ.get("VULNCATCHER_PRO_MODEL", "gemini-3.1-pro")
    gemma_endpoint = os.environ.get("VULNCATCHER_GEMMA_ENDPOINT")

    if not model_name.startswith("gemini-"):
        LiteLlm = _get_stripped_litellm()
        if gemma_endpoint:
            litellm_model = (
                model_name
                if model_name.startswith("openai/")
                else f"openai/{model_name}"
            )
            return LiteLlm(
                model=litellm_model, api_base=gemma_endpoint, api_key="none"
            )
        else:
            return LiteLlm(model=model_name, drop_params=True)

    if gemma_endpoint:
        LiteLlm = _get_stripped_litellm()
        # Prepend openai/ if not present to route via LiteLlm OpenAI-compatible wrapper
        litellm_model = (
            model_name
            if model_name.startswith("openai/")
            else f"openai/{model_name}"
        )
        return LiteLlm(
            model=litellm_model, api_base=gemma_endpoint, api_key="none"
        )
    client_kwargs = {}
    if not os.environ.get("GEMINI_API_KEY"):
        import google.auth

        try:
            _, project_id = google.auth.default()
        except:
            project_id = None
        project_id = (
            os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("VULNCATCHER_PROJECT")
            or project_id
        )
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
        if project_id:
            client_kwargs = {
                "vertexai": True,
                "project": project_id,
                "location": location,
            }

    Gemini = _get_stripped_gemini()
    return Gemini(
        model=model_name,
        retry_options=types.HttpRetryOptions(attempts=3),
        client_kwargs=client_kwargs,
    )


def _model_fast():
    model_name = os.environ.get("VULNCATCHER_FLASH_MODEL", "gemini-3.5-flash")
    gemma_endpoint = os.environ.get("VULNCATCHER_GEMMA_ENDPOINT")

    if not model_name.startswith("gemini-"):
        LiteLlm = _get_stripped_litellm()
        if gemma_endpoint:
            litellm_model = (
                model_name
                if model_name.startswith("openai/")
                else f"openai/{model_name}"
            )
            return LiteLlm(
                model=litellm_model, api_base=gemma_endpoint, api_key="none"
            )
        else:
            return LiteLlm(model=model_name, drop_params=True)

    if gemma_endpoint:
        LiteLlm = _get_stripped_litellm()
        litellm_model = (
            model_name
            if model_name.startswith("openai/")
            else f"openai/{model_name}"
        )
        return LiteLlm(
            model=litellm_model, api_base=gemma_endpoint, api_key="none"
        )
    client_kwargs = {}
    if not os.environ.get("GEMINI_API_KEY"):
        import google.auth

        try:
            _, project_id = google.auth.default()
        except:
            project_id = None
        project_id = (
            os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("VULNCATCHER_PROJECT")
            or project_id
        )
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
        if project_id:
            client_kwargs = {
                "vertexai": True,
                "project": project_id,
                "location": location,
            }

    Gemini = _get_stripped_gemini()
    return Gemini(
        model=model_name,
        retry_options=types.HttpRetryOptions(attempts=3),
        client_kwargs=client_kwargs,
    )


DETERMINISTIC_CONFIG = types.GenerateContentConfig(temperature=0.0)
"""GenerateContentConfig with temperature=0, applied per-Agent (not per-Model).

Used for agents where exploration variance is undesirable — primarily the LLM
discovery agent, whose stochastic skill-selection / grep-pattern choices caused
per-run rubric variance during eval iterations (see tests/eval/RESULTS.md).
"""


SCANNER_DISCOVERY_INSTRUCTION = """\
You are the scanner-driven half of the discovery phase.

The user message contains a TARGET_PATH (an absolute filesystem path to a
codebase root). Extract it.

Run these steps in order:
1. Call detect_languages(target_path) to learn what languages are present.
2. Call run_semgrep(target_path).
3. Call run_trivy(target_path).
4. Call run_gitleaks(target_path).
5. If "python" is in the detected languages, call run_bandit(target_path).

After all tool calls return, emit a single JSON object describing what was
found. Top-level keys: target_path (string), languages (list of strings),
scanners (object keyed by scanner name; each value is the tool's return dict).
Output only the JSON object — no prose, no Markdown fences.
"""


LLM_DISCOVERY_INSTRUCTION = f"""\
You are the AI-driven half of the discovery phase. You orchestrate
detection skills against a target codebase using your training knowledge and
the tools you have. You do NOT call third-party scanners — that's the other
discovery agent's job.

The user message contains a TARGET_PATH (an absolute filesystem path to a
codebase root). Extract it.

## Available detection skills

Each skill is a focused playbook for one vulnerability class: where to look,
which grep_code patterns to run, what confirms a real finding vs a false
positive, and what severity/CWE/rule_id to assign. Call load_skill(skill_id)
to read the full procedure for any skill that looks relevant.

{_build_skill_index('detection')}

## Workflow

1. Call `map_boundaries(target_path)` to harvest dynamic attack-surface entry points (HTTP routes, controllers) or system interface boundaries (syscalls, ioctl handlers).
2. Call `list_dir(target_path, max_depth=2)` for a structural overview.
3. Decide which detection skills apply based on the codebase.
4. For EACH applicable skill: call `load_skill(skill_id)`.
   * **SOTA Targeted Scaling Rule:** If `map_boundaries` successfully returned a list of `boundary_files`, you **MUST** target your playbook walks, file reads (`read_code_window`), and fallback audits **strictly on these boundary files and their imported mappers**. Do not perform expensive global codebase walks outside this attack-surface boundary!
5. AFTER skills: a brief fallback exploration pass for novel or zero-day patterns the skills don't cover, focusing strictly around the discovered boundary and syscall files. Be conservative — only flag things you can defend with concrete code evidence.

## Output

Emit a single JSON object with EXACTLY these keys:
- target_path (string)
- findings (array). Each finding MUST be a standardized OASIS SARIF v2.1.0 compliant object containing:
    - ruleId: short slug — use the skill's suggested slug when applicable
             (e.g. "ai.csrf-disabled", "ai.idor"), otherwise pick
             a similar ai.<class> shape.
    - level: the severity mapped to: "error" (for critical/high) | "warning" (for medium/low) | "note" (for info).
    - message: {{"text": "1-2 sentence description of what's wrong"}}
    - locations: [
        {{
          "physicalLocation": {{
            "artifactLocation": {{"uri": "relative path to file"}},
            "region": {{"startLine": 1-indexed line number where the issue is}}
          }}
        }}
      ]
    - properties: {{
        "scanner": "ai",
        "cwe": list of CWE ids as strings (e.g. ["CWE-89"]),
        "evidence": "exact code lines matched",
        "rationale": "1-3 sentences explaining why this is exploitable"
      }}

Output only the JSON object — no prose, no Markdown fences.
"""


TRIAGE_INSTRUCTION = """\
You are a senior application security reviewer acting as the **triage critic**
for this scan. Two upstream discovery agents (scanner-driven and AI-driven)
produced raw findings in session state.

Both sources now output standardized OASIS SARIF v2.1.0 findings:

Scanner-driven findings (from semgrep/trivy/gitleaks/bandit):
{scanner_findings}

AI-driven findings (LLM reasoning over the codebase):
{llm_findings}

Your job: treat the union of both as your input, dedupe, and then
**adversarially triage each surviving finding**. For every finding, your
default question is "can I prove this is NOT actually exploitable?" before
you accept it as real. This is what a careful human reviewer would do; it
keeps the validation phase focused on findings that genuinely deserve deep
inspection.

## Step 1 — Dedupe

- Drop exact duplicates (same file uri in locations, same startLine in locations, and same ruleId, regardless of scanner).
- When a Gemini finding and a scanner finding describe the same underlying
  issue at the same file:line (different ruleId but clearly overlapping),
  keep the one with stronger evidence (usually the scanner) and note the
  agreement in `properties.reasoning` ("corroborated by gemini" / "corroborated by
  semgrep"). Cross-source corroboration is a strong TRUE_POSITIVE signal —
  weight it accordingly in confidence_score.
- **Cluster Trivy vulnerable-dependency findings.** If multiple
  `trivy.vuln.*` findings hit the same manifest file, consolidate them into
  ONE representative SARIF finding object with:
    - `ruleId`: "trivy.vuln-summary"
    - `level`: the highest severity level in the cluster
    - `message`: {"text": "N known-vulnerable packages in <manifest>. Top: <up to 5 pkg@version (CVE-ID) by severity>."}
    - `locations`: [
        {
          "physicalLocation": {
            "artifactLocation": {"uri": manifest_path},
            "region": {"startLine": 0}
          }
        }
      ]
    - `properties`: {
        "scanner": "trivy",
        "cwe": consolidated CweIDs list,
        "reasoning": "Enumeration of CVEs. SCA findings from Trivy's CVE database — no per-line code reading needed; remediation is to upgrade the listed packages."
      }
  This prevents a single noisy lockfile from eating the validation cap. Keep all other Trivy classes (secrets, misconfigs) as individual findings.

## Step 2 — Adjudicate (TRUE_POSITIVE or FALSE_POSITIVE)

For each surviving finding, judge it on two angles:

- **Reachability**: Is the vulnerable code path actually exposed to an
  attacker? Public route handler vs internal helper never called by user
  input, production code vs test/spec/fixture, always-on vs gated behind
  a feature flag. Findings in `test/`, `tests/`, `*_spec.*`, `*.test.*`,
  `cypress/`, `e2e/` directories should almost always be FALSE_POSITIVE.
- **Sanitization / mitigation in place**: Is there a framework auto-defense
  (Django CSRF middleware on by default, ORM parameter binding, default
  template autoescape), an explicit sanitizer call (DOMPurify, encoders,
  validators), or input validation that neutralizes the payload before it
  reaches the sink?

Rules:
- If you can construct a defensible argument that the finding is unreachable
  by an attacker OR is neutralized before the sink → **FALSE_POSITIVE**.
- Otherwise → **TRUE_POSITIVE**.
- When you genuinely cannot tell from the finding metadata alone, **use your
  tools to verify**: call `read_code_window` to inspect the actual source
  code around the finding location, and `find_references` to trace callers
  and data flow. Make your adjudication based on concrete code evidence
  rather than assumptions. Prefer **TRUE_POSITIVE** with a lower
  `confidence_score` only when even after reading the code you remain unsure.

## Step 3 — Rank

Rank from 1 (most urgent) downward. Sort key, in priority order:
1. `adjudication`: TRUE_POSITIVE before FALSE_POSITIVE
2. `level`: error > warning > note
3. `confidence_score`: descending

## Output

A JSON array of standardized SARIF findings (capped at top 25). Each element
must be a valid SARIF finding object. Inside `properties` you MUST include:
- `scanner` (semgrep | trivy | gitleaks | bandit | gemini)
- `adjudication` (TRUE_POSITIVE | FALSE_POSITIVE)
- `confidence_score` (integer 1-100)
- `reasoning` (1-2 sentences explaining the adjudication)
- `rank` (integer, 1 = most urgent)

Include both TRUE_POSITIVE and FALSE_POSITIVE findings — downstream validation
uses the adjudication to decide which files to read. Output only the JSON
array, no prose, no Markdown fences.
"""


VALIDATION_INSTRUCTION = f"""\
You are the validation phase of a vulnerability scanner.

Triaged findings from the previous phase are in session state below:

{{triaged_findings}}

You are provided with an array of triaged standardized SARIF findings.
For each of the **top 15 findings by rank where properties.adjudication == "TRUE_POSITIVE"**
(skip findings the Triage Critic already adjudicated as FALSE_POSITIVE):

1. Extract the file URI from `locations[0].physicalLocation.artifactLocation.uri` and the line number from `locations[0].physicalLocation.region.startLine`.
2. Call `read_code_window` with the file path, start_line set to max(1, line - 5), and end_line set to line + 15.
3. Decide whether the finding is real (validated=true) or appears to be a false positive (validated=false), based on whether the surrounding code matches the vulnerability pattern.
4. Write a 1-3 sentence evidence note referencing what you saw in the code.

## Available validation playbooks

Before attempting dynamic validation of a finding, check if a structured
validation playbook exists for that vulnerability class. Call
`load_skill(skill_id, category="validation")` to load the full procedure.
Follow the playbook's step-by-step instructions for mock setup, exploit
script synthesis, and result interpretation.

{_build_skill_index('validation')}

## Symbol & Caller Tracing (For Exploit Chains & Reachability)
If the suspect vulnerability resides inside an internal helper, library, or data-access function, you should trace its data flow up to a public controller, handler, or API route.
- Call `find_references(symbol, target_path)` using the function name or variable name as the `symbol` to locate where it is invoked across other files.
- Call `read_code_window` on those caller locations to verify if untrusted user input reaches the parameter.
- Use this trace information to construct and validate **EXPLOIT CHAINS**: pairs or triples of findings where one's data flow feeds another's sink.

## Dynamic Sandbox Validation
For high-severity vulnerabilities that allow dynamic execution verification (such as JavaScript `eval()`, command injection, SQL/NoSQL injection, or Path Traversal):
- Read the entire target code snippet using `read_code_window` to capture the exact function implementation.
- Synthesize a short, self-contained exploit validation script as `payload_content` (e.g., calling the target's function with adversarial input values).
- **SOTA Dynamic AST Mocking Rule (Database & Network Isolation):** Because the sandbox runs in a highly secure, network-muted environment (`--network none`), any database or external network connections inside the target code will fail. You **MUST** dynamically write and inject mock stubs (e.g. using `sinon` or simple function/module overrides) at the very top of your generated `payload_content` to mock any imported database clients (such as `mongoose`, `pg`, `mysql2`, `redis`, or Python's `pymongo`) or HTTP clients. Configure these stubs to connect instantly and return standard dummy query results. This bypasses all database connection requirements, ensuring 100% successful exploit execution inside the muted container!
- Invoke `execute_in_sandbox(code_content, payload_content, language)` (specify language as "javascript" or "python" based on the target runtime).
- Check the returned result: if the output or exit code indicates successful payload reachability/injection, mark the finding as `validated: true`, set `validation_type: "DYNAMIC"`, and include the sandbox stdout/stderr in your `validation_evidence`! If the sandbox crashes or is unavailable (e.g. exit 127), fall back to static analysis and set `validation_type: "STATIC"` if the vulnerability is still statically proven.

**Exception for non-code findings** (ruleId starts with `trivy.vuln`,
`trivy.secret`, `trivy.misconfig`, or any finding where `startLine` == 0):
  - Skip the `read_code_window`/`find_references`/`execute_in_sandbox` calls.
  - Set `validated: true` (trust the upstream scanner).
  - For `evidence`, **copy the message.text verbatim** — specifically
    preserve any CVE IDs, package@version strings, file paths, and concrete facts.

Output a single JSON object with two keys:
- validated: an array of standardized SARIF findings, where each verified finding has its `properties` enriched with:
    "validated": true | false,
    "validation_type": "STATIC" | "DYNAMIC",
    "validation_evidence": "..."
- exploit_chains: an array of objects (possibly empty), each with description
  and finding_refs (a list of identifiers in "ruleId@file:line" form).

Output only the JSON object, no prose, no Markdown fences.
"""


REMEDIATION_INSTRUCTION = """\
You are the autogenous remediation phase of a vulnerability scanner.

Validated findings from the previous validation phase are in session state below:

{validated_findings}

For each of the validated standardized SARIF findings in this list where properties.validated == true:
1. Call `read_code_window` to fetch the target file's context.
2. Synthesize a safe, precise code fix adhering strictly to secure coding rules.
3. Output a clean Unified Git Diff string (in standard unified diff format) representing the exact lines to remove (-) and insert (+).
4. Add the generated diff to the finding's properties as `patch_diff`.
5. **Post-Patch Verification:** After generating the patch, call
   `execute_in_sandbox(patched_code_content, exploit_payload, language)` to
   re-run the original exploit payload against the PATCHED version of the code.
   Verify that the exploit FAILS (non-zero exit code, no injection output, or
   caught exception). Record the verification result in `patch_verified`: true/false.
   If verification fails, revise the patch and re-test. Crucial limit: You must not attempt to revise and re-test a single patch more than 2 times. If the patch verification fails on the second revision, set `patch_verified` to false, document the failure in `validation_evidence` along with the final diff, and proceed to the next finding.

Output a single JSON object:
- remediated_findings: the array of standardized SARIF findings, where each validated finding is enriched with:
    "properties": {
        "validated": true,
        "validation_evidence": "...",
        "patch_diff": "...",
        "patch_verified": true | false
    }

Output only the JSON object, no prose, no Markdown fences.
"""


REPORT_INSTRUCTION = """\
You are the report phase. Write a clear Markdown report for a developer who
is NOT a security expert and wants to fix real vulnerabilities while ignoring
noise.

Validated & Remediated findings input (standardized SARIF) is in session state below:

{remediated_findings}

Compose Markdown with these sections, in order:
- A top-level heading: "VulnCatcher report — <ISO timestamp>".
- An "Executive summary" section: A highly detailed, 1-2 paragraph developer-friendly overview written in plain, non-cryptic English:
  * Summarize the exact types of vulnerabilities discovered (e.g., eval-based RCE, NoSQL injection, IDOR, hardcoded credentials) and identify which core components or directories are impacted.
  * Translate the real-world security impacts of the top risks clearly (e.g. explain that "eval-based RCE allows unauthenticated remote attackers to take full control of the host server", or "plaintext password storage exposes customer databases to instant leaks").
  * Outline the high-level, recommended technical remediation strategy to achieve secure-by-default status (e.g. "using standard input parsing libraries, sanitizing query boundaries, enabling cookie session env keys, and activating global HTML autoescape middlewares").
  * State whether any composite multi-step exploit chains were identified.
  * Ensure this is framed specifically for a generalist developer who is not a security expert, so they can instantly grasp the threat landscape and technical remediation path.
- A "Findings table" section: a Markdown table with columns
  Severity | File:Line | Rule | Status (e.g., Validated [STATIC], Validated [DYNAMIC], or False Positive).
  (Severity is derived from the SARIF `level`: "error" -> Critical/High, "warning" -> Medium/Low, "note" -> Info).
- A "Detailed findings" section: one third-level subsection per validated
  finding. Each subsection MUST include a tag like `[✅ STATICALLY VALIDATED]` or `[🔥 DYNAMICALLY VALIDATED]` in its title based on `properties.validation_type`, and include BOTH of these fields, in order:
    - **Evidence:** the 1-3 sentence evidence note from validation.
    - **Remediation:** a CONCRETE fix recommendation. **Grounding rule:** the
      remediation must reference patterns, identifiers, or upgrade targets
      that are EITHER (a) directly visible in this finding's Evidence note
      (e.g., the validation observed `eval(req.body.preTax)`, so the
      remediation can say "Replace the `eval(req.body.preTax)` call with
      `parseInt(req.body.preTax, 10)`"), OR (b) directly visible in the
      finding's scanner output (e.g., a Trivy vuln finding provides
      `installed_version` and `fixed_version`, so "Upgrade `bson` from
      `1.0.9` to `≥1.1.4`" is grounded). Acceptable shapes:
        - Specific code change anchored in observed code.
        - Named library/middleware/config to enable, by canonical name only
          (e.g., "Register `csurf` middleware", NOT a fabricated
          `app.use(csurf({ cookie: true }))` snippet that wasn't observed).
        - Upgrade path with versions taken from scanner output.
        - For categories where the fix is well-known but the specifics weren't
          observed (e.g., generic "use environment variables for secrets"),
          phrase as a one-line standard reference, not as invented code.
      What is NOT acceptable: inventing specific code snippets (function
      names, parameter shapes, configuration constants) that did not appear
      in the validation evidence or scanner output. Generic "fix this" /
      "review for security" / "consult documentation" is also not acceptable.
- An "Exploit chains" section: include only if there are any chains; describe
  each in plain English with references to the contributing findings.

Then call write_report with the full Markdown as `content` and a filename of
the form "vulncatcher-YYYYMMDD-HHMMSS" (use the same timestamp from the
heading).

After write_report returns, reply with a final response in this exact format:

    Report saved to <absolute_path>.

    <full Markdown body as you passed it to write_report>

Include the full Markdown body verbatim after the "Report saved to ..." line
so downstream consumers (CLI users, evaluators) can see the report content
without opening the file.
"""


scanner_discovery_agent = Agent(
    name="scanner_discovery_agent",
    model=_model_fast(),
    description="Runs SAST/SCA/secrets scanners against the target codebase.",
    instruction=SCANNER_DISCOVERY_INSTRUCTION,
    tools=[detect_languages, run_semgrep, run_trivy, run_gitleaks, run_bandit],
    output_key="scanner_findings",
)


llm_discovery_agent = Agent(
    name="llm_discovery_agent",
    model=_model_fast(),
    generate_content_config=DETERMINISTIC_CONFIG,
    description="AI-driven vulnerability discovery using a skill-directory of detection playbooks.",
    instruction=LLM_DISCOVERY_INSTRUCTION,
    tools=[
        list_dir,
        grep_code,
        query_ast,
        read_code_window,
        load_skill,
        map_boundaries,
    ],
    output_key="llm_findings",
)


discovery_phase = ParallelAgent(
    name="discovery_phase",
    description="Runs scanner-driven and AI-driven discovery concurrently.",
    sub_agents=[scanner_discovery_agent, llm_discovery_agent],
)


triage_agent = Agent(
    name="triage_agent",
    model=_model(),
    generate_content_config=DETERMINISTIC_CONFIG,
    description="Dedupes, filters false positives, and ranks raw findings.",
    instruction=TRIAGE_INSTRUCTION,
    tools=[read_code_window, find_references],
    output_key="triaged_findings",
)


validation_agent = Agent(
    name="validation_agent",
    model=_model(),
    description="Validates triaged findings by reading code and reasoning about exploitability.",
    instruction=VALIDATION_INSTRUCTION,
    tools=[read_code_window, find_references, execute_in_sandbox, load_skill],
    output_key="validated_findings",
)


remediation_agent = Agent(
    name="remediation_agent",
    model=_model(),
    generate_content_config=DETERMINISTIC_CONFIG,
    description="Synthesizes safe, compiler-verified code fix patches (Diffs) for validated findings.",
    instruction=REMEDIATION_INSTRUCTION,
    tools=[
        read_code_window,
        grep_code,
        find_references,
        list_dir,
        map_boundaries,
        execute_in_sandbox,
    ],
    output_key="remediated_findings",
)


report_agent = Agent(
    name="report_agent",
    model=_model(),
    description="Writes the final Markdown vulnerability report to ./reports/.",
    instruction=REPORT_INSTRUCTION,
    tools=[write_report],
)


root_agent = SequentialAgent(
    name="root_agent",
    description="VulnCatcher vulnerability scanning pipeline: discover → triage → validate → remediate → report.",
    sub_agents=[
        discovery_phase,
        triage_agent,
        validation_agent,
        remediation_agent,
        report_agent,
    ],
)


app = App(
    root_agent=root_agent,
    name="app",
    plugins=[ScannerAllowlistPlugin()],
)
