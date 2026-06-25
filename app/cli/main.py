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

"""Main CLI entry point for Reference Harness vulnerability scanner."""

import argparse
import concurrent.futures
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import requests
from app.cli.bootstrap import bootstrap_codebase_signatures
from app.cli.models import select_gcp_vertex_models
from app.cli.results import compile_and_render_results
from app.cli.server import ADKServerManager
from app.cli.streaming import get_active_line_text
from app.tools import map_boundaries
from google.cloud import storage
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


def extract_json_objects(text):
    objs = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    start = 0
    while True:
        pos = text.find("{", start)
        if pos == -1:
            break
        bracket_count = 0
        in_string = False
        escape = False
        end = -1
        for i in range(pos, len(text)):
            char = text[i]
            if escape:
                escape = False
                continue
            if char == "\\":
                escape = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if not in_string:
                if char == "{":
                    bracket_count += 1
                elif char == "}":
                    bracket_count -= 1
                    if bracket_count == 0:
                        end = i
                        break
        if end != -1:
            sub_str = text[pos : end + 1]
            try:
                obj = json.loads(sub_str)
                if isinstance(obj, dict):
                    objs.append(obj)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
            start = end + 1
        else:
            start = pos + 1
    return objs


def extract_validated_findings(text):
    findings = []
    objs = extract_json_objects(text)

    def search_findings(data):
        results = []
        if isinstance(data, list):
            for item in data:
                results.extend(search_findings(item))
        elif isinstance(data, dict):
            if "ruleId" in data and isinstance(data["ruleId"], str):
                results.append(data)
            else:
                for val in data.values():
                    if isinstance(val, (list, dict)):
                        results.extend(search_findings(val))
        return results

    flat_findings = search_findings(objs)
    for obj in flat_findings:
        rule = obj.get("ruleId")
        uri = None
        locations = obj.get("locations", [])
        if locations and isinstance(locations, list):
            try:
                uri = locations[0]["physicalLocation"]["artifactLocation"][
                    "uri"
                ]
            except (KeyError, IndexError, TypeError):
                pass
        if not uri:
            uri = obj.get("uri")
        if not uri or not isinstance(uri, str):
            uri = "?"

        val_type = obj.get("validation_type")
        if not val_type or not isinstance(val_type, str):
            val_type = "STATIC"

        cve = None
        props = obj.get("properties", {})
        if isinstance(props, dict):
            cve = props.get("cve")
        if not cve:
            cve = obj.get("cve")
        if not cve:
            obj_str = json.dumps(obj)
            cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", obj_str)
            if cve_match:
                cve = cve_match.group(1)

        is_val = obj.get("validated")
        if is_val is None and isinstance(props, dict):
            is_val = props.get("validated")
        if is_val is False or str(is_val).lower() == "false":
            continue

        findings.append(
            {"rule": rule, "uri": uri, "val_type": val_type, "cve": cve}
        )
    return findings


def _fallback_extract_findings(text):
    rule_matches = re.findall(r'"ruleId":\s*"([^"]+)"', text)
    uri_matches = re.findall(r'"uri":\s*"([^"]+)"', text)
    val_type_matches = re.findall(r'"validation_type":\s*"([^"]+)"', text)
    cve_matches = re.findall(r"(CVE-\d{4}-\d{4,7})", text)
    res = []
    for r_idx, rule in enumerate(rule_matches):
        uri = uri_matches[r_idx] if r_idx < len(uri_matches) else "?"
        vtype = (
            val_type_matches[r_idx]
            if r_idx < len(val_type_matches)
            else "STATIC"
        )
        cve = cve_matches[0] if cve_matches else None
        res.append({"rule": rule, "uri": uri, "val_type": vtype, "cve": cve})
    return res


def _log_validated_finding(f_item, feedback_logs, con):
    rule = f_item["rule"]
    uri = f_item["uri"]
    key = f"{rule}@{uri}"
    if key in feedback_logs:
        return False
    feedback_logs.add(key)
    val_type = f_item["val_type"]
    cve = f_item["cve"]
    cve_str = f"{cve} (" if cve else ""
    cve_suffix = ")" if cve else ""
    f_base = os.path.basename(uri)
    msg = (
        "🔥 [bold red]Vulnerability Validated ("
        f"{val_type}):[/] [bold magenta]{cve_str}[/][underline yellow]"
        f"{rule}[/][bold magenta]{cve_suffix}[/] inside [underline]{f_base}[/]"
    )
    con.print(msg)
    return True


def _process_validated_event(text, feedback_logs, con):
    findings = extract_validated_findings(text)
    if not findings:
        findings = _fallback_extract_findings(text)
    count = 0
    for f_item in findings:
        if _log_validated_finding(f_item, feedback_logs, con):
            count += 1
    return count


def _update_cnt(cnt, text, logs, con):
    if "validated" not in text.lower():
        return cnt
    if '"validated": true' not in text.lower():
        return cnt
    try:
        return cnt + _process_validated_event(text, logs, con)
    except (ValueError, KeyError, TypeError):
        return cnt


# Set up logging for CLI execution
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("vulncatcher-cli")
# Disable debug logs on stdout for cleaner rich UX unless requested
if os.environ.get("VULNCATCHER_DEBUG") != "1":
    logging.getLogger().setLevel(logging.WARNING)


def main():
    console = Console()

    parser = argparse.ArgumentParser(
        description="Reference Harness Security Audit Engine"
    )
    parser.add_argument("target_dir", help="Target directory path to scan")
    parser.add_argument(
        "--pro-model", help="Override the deep-reasoning PRO model name"
    )
    parser.add_argument(
        "--flash-model", help="Override the fast-discovery FLASH model name"
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=25,
        help="Max number of boundary files processed in each chunk batch",
    )
    parser.add_argument(
        "--location", help="Override the GCP Vertex AI region location"
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Concurrent workers for executing chunked scan batches",
    )
    parser.add_argument(
        "--scan-all",
        action="store_true",
        help="Bypass filters and scan every source file in directory",
    )
    parser.add_argument(
        "--output-format",
        default="markdown",
        choices=["markdown", "sarif", "both"],
        help="Format of the output report",
    )
    parser.add_argument(
        "--gcs-bucket",
        help="GCS bucket name to upload the generated consolidated reports",
    )
    parser.add_argument(
        "--gcs-prefix",
        default="",
        help="Optional folder prefix path inside the GCS bucket",
    )
    parser.add_argument(
        "--gemma-endpoint",
        help="Cloud Run URL or proxy endpoint for running Gemma 4 vLLM",
    )

    args = parser.parse_args()
    target_dir = args.target_dir

    if not os.path.exists(target_dir):
        console.print(f"[bold red]Error:[/] Directory not found: {target_dir}")
        sys.exit(1)

    console.print(r"""[bold green]
    ____  ______________________  _______   ______________
   / __ \/ ____/ ____/ ____/ __ \/ ____/ | / / ____/ ____/
  / /_/ / __/ / /_  / __/ / /_/ / __/ /  |/ / /   / __/
 / _, _/ /___/ __/ / /___/ _, _/ /___/ /|  / /___/ /___
/_/ |_/_____/_/   /_____/_/ |_/_____/_/ |_/\____/_____/

    __  _____    ____  _   __________________
   / / / /   |  / __ \/ | / / ____/ ___/ ___/
  / /_/ / /| | / /_/ /  |/ / __/  \__ \\__ \
 / __  / ___ |/ _, _/ /|  / /___ ___/ /__/ /
/_/ /_/_/  |_/_/ |_/_/ |_/_____//____/____/
[/]""")

    console.print(
        Panel.fit(
            "[bold green]Reference Harness Security Audit Engine — v0.4.4[/]\n"
            f"[dim]Target Path:[/] {os.path.abspath(target_dir)}",
            border_style="green",
        )
    )

    gcs_bucket = args.gcs_bucket
    if gcs_bucket:
        gcs_bucket = gcs_bucket.strip("“\"'”‘’")
        console.print(
            "[bold yellow]↻ Verifying GCS bucket [underline cyan]"
            f"{gcs_bucket}[/] exists...[/]"
        )
        try:
            storage_client = storage.Client()
            bucket = storage_client.lookup_bucket(gcs_bucket)
            if not bucket:
                console.print(
                    "[bold red]Error:[/] GCS bucket [underline cyan]"
                    f"{gcs_bucket}[/] does not exist or is not accessible."
                )
                sys.exit(1)
            console.print(
                f"[bold green]✓ Verified GCS bucket [underline cyan]"
                f"{gcs_bucket}[/] exists.[/]"
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            # Catching Exception because GCP storage lookup errors vary
            console.print(
                "[bold red]Error verifying GCS bucket [underline cyan]"
                f"{gcs_bucket}[/]:[/] {str(e)}"
            )
            console.print("[dim]Please check connection or ADC permissions.[/]")
            sys.exit(1)

    # Set location env var early so bootstrapper uses it for model routing
    if args.location:
        os.environ["GOOGLE_CLOUD_LOCATION"] = args.location

    pro_model, flash_model = select_gcp_vertex_models(
        pro_override=args.pro_model,
        flash_override=args.flash_model,
        location_override=args.location,
        gemma_endpoint=args.gemma_endpoint,
    )

    boot_data = bootstrap_codebase_signatures(target_dir, flash_model)
    package_root = Path(__file__).parent.parent
    adk_dir = package_root / ".adk"
    os.makedirs(str(adk_dir), exist_ok=True)

    boot_path = str(adk_dir / "bootstrapped_signatures.json")
    if boot_data:
        with open(boot_path, "w", encoding="utf-8") as f:
            json.dump(boot_data, f, indent=2)
    else:
        if os.path.exists(boot_path):
            try:
                os.remove(boot_path)
            except OSError as e:
                logger.warning(
                    "Failed to remove bootstrapped signatures: %s", e
                )

    env = os.environ.copy()
    env["UV_NO_SYNC"] = "1"
    env["ADK_LOG_LEVEL"] = "ERROR"
    env["PYTHONWARNINGS"] = "ignore"
    env["PYTHONUNBUFFERED"] = "1"
    env["VULNCATCHER_PRO_MODEL"] = pro_model
    env["VULNCATCHER_FLASH_MODEL"] = flash_model
    if args.location:
        env["GOOGLE_CLOUD_LOCATION"] = args.location
    if args.gemma_endpoint:
        env["VULNCATCHER_GEMMA_ENDPOINT"] = args.gemma_endpoint

    server_manager = ADKServerManager()
    server_manager.force_kill_port(server_manager.active_server_port)

    db_path = str(adk_dir / "session.db")
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError as e:
            logger.warning("Failed to remove active session db: %s", e)

    for suffix in ["-wal", "-journal", "-shm"]:
        p = db_path + suffix
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError as e:
                logger.warning(
                    "Failed to remove database journal helper: %s", e
                )

    subprocess.run(
        ["agents-cli", "run", "--stop-server"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )

    if args.scan_all:
        console.print(
            "[bold yellow]↻ Deep Scan Mode: Bypassing boundary filters "
            "and mapping all source files...[/]"
        )
        boundary_files = []
        skip_dirs = {
            ".git",
            "node_modules",
            ".venv",
            "venv",
            "dist",
            "build",
            ".adk",
            "target",
            "out",
            "__pycache__",
            "reports",
        }
        skip_exts = {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".pdf",
            ".db",
            ".zip",
            ".tar",
            ".gz",
            ".lock",
            ".class",
            ".o",
            ".so",
            ".jar",
            ".war",
            ".pyc",
        }

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for file in files:
                _, ext = os.path.splitext(file.lower())
                if ext not in skip_exts:
                    boundary_files.append(os.path.join(root, file))
        boundary_files = sorted(boundary_files)
    else:
        boundary_res = map_boundaries(target_dir)
        boundary_files = sorted(boundary_res.get("boundary_files", []))

    boundary_log_path = str(adk_dir / "boundary_files.log")
    try:
        with open(boundary_log_path, "w", encoding="utf-8") as lf:
            count_str = str(len(boundary_files))
            lf.write(
                "=== HARVESTED ACTIVE CODEBASE BOUNDARIES "
                f"({count_str} files) ===\n\n"
            )
            for f_path in boundary_files:
                lf.write(f"• {f_path}\n")
    except OSError as e:
        logger.warning("Failed to write codebase boundaries log: %s", e)

    batch_size = args.chunk_size
    batches = [
        boundary_files[i : i + batch_size]
        for i in range(0, len(boundary_files), batch_size)
    ]
    if not batches:
        batches = [[]]

    console.print(
        f"[bold green]✓ Codebase boundaries compiled: [underline cyan]"
        f"{len(boundary_files)}[/] files split into [underline cyan]"
        f"{len(batches)}[/] Chunked Batches.[/]"
    )

    port = server_manager.start_adk_server(env)
    run_url = f"http://127.0.0.1:{port}/run_sse"

    batch_session_ids = []
    start_time = time.time()

    parallel_workers = getattr(args, "parallel", 1)
    if not isinstance(parallel_workers, int):
        try:
            parallel_workers = int(parallel_workers)
        except (ValueError, TypeError):
            parallel_workers = 1

    if parallel_workers > 1:
        lock = threading.Lock()
        batch_states = {}

        # Initialize queued state for all batches
        for b_idx in range(len(batches)):
            batch_states[b_idx] = {
                "status": "queued",
                "phase_name": "Queued",
                "current_tool": "",
                "validated_findings": 0,
                "elapsed": 0.0,
            }

        def render_progress_panel():
            table = Table(box=None, padding=(0, 2))
            table.add_column("Batch", style="cyan", width=18)
            table.add_column("Phase/Status", style="green")
            table.add_column("Active Tool", style="yellow")
            table.add_column("Findings", style="red")
            table.add_column("Elapsed", style="magenta")

            with lock:
                for b_idx in range(len(batches)):
                    state = batch_states.get(
                        b_idx,
                        {
                            "status": "queued",
                            "phase_name": "Queued",
                            "current_tool": "",
                            "validated_findings": 0,
                            "elapsed": 0.0,
                        },
                    )

                    status = state["status"]
                    phase_name = state["phase_name"]
                    current_tool = state["current_tool"]
                    validated_findings = state["validated_findings"]
                    elapsed = state["elapsed"]

                    findings_str = (
                        f"{validated_findings} validated"
                        if validated_findings > 0
                        else "-"
                    )
                    elapsed_str = f"{elapsed:.1f}s" if elapsed > 0 else "-"
                    tool_str = current_tool if current_tool else "-"

                    if status == "completed":
                        phase_display = "[bold green]✓ Completed[/]"
                        tool_str = "-"
                    elif status == "failed":
                        phase_display = "[bold red]✗ Failed[/]"
                        tool_str = "-"
                    elif status == "queued":
                        phase_display = "[dim]Queued...[/]"
                        tool_str = "-"
                    else:
                        phase_display = f"[bold yellow]▰▰▰[/] {phase_name}"

                    table.add_row(
                        f"Chunk Batch {b_idx+1}/{len(batches)}",
                        phase_display,
                        tool_str,
                        findings_str,
                        elapsed_str,
                    )
            return Panel(
                table,
                title=(
                    "[bold green]Reference Harness Concurrent Audit "
                    "Progress[/]"
                ),
                border_style="green",
            )

        def execute_batch_parallel(batch_idx, batch):
            batch_start_time = time.time()
            with lock:
                batch_states[batch_idx] = {
                    "status": "starting",
                    "phase_name": "Starting Reference Harness...",
                    "current_tool": "",
                    "validated_findings": 0,
                    "elapsed": 0.0,
                }

            for attempt in range(3):
                try:
                    s_base = (
                        f"http://127.0.0.1:{port}/apps/app/"
                        "users/cli-user/sessions"
                    )
                    session_resp = requests.post(s_base, json={}, timeout=120)
                    if not session_resp.ok:
                        err_text = session_resp.text
                        raise RuntimeError(
                            f"Failed to create chunk session "
                            f"(HTTP {session_resp.status_code}): {err_text}"
                        )

                    current_session_id = session_resp.json().get("id")

                    if batch:
                        batch_paths = [os.path.abspath(p) for p in batch]
                        b_json = json.dumps(batch_paths)
                        initial_prompt = (
                            f"Scan {os.path.abspath(target_dir)} "
                            "focusing strictly on these boundary files: "
                            f"{b_json}. Validate and remediate."
                        )
                    else:
                        initial_prompt = (
                            f"Scan {os.path.abspath(target_dir)} "
                            "for vulnerabilities and write a report."
                        )

                    phases = [
                        {
                            "key": "start",
                            "name": "Starting Reference Harness...",
                            "match": None,
                        },
                        {
                            "key": "scanners",
                            "name": (
                                "Executing static scanners "
                                "(Semgrep/Trivy/Gitleaks/Bandit)"
                            ),
                            "match": "scanner_allowlist",
                        },
                        {
                            "key": "llm_discovery",
                            "name": "Auditing codebase (AI playbooks)",
                            "match": "llm_discovery_agent",
                        },
                        {
                            "key": "triage",
                            "name": "Triage Critic filtering FPs",
                            "match": "triage_agent",
                        },
                        {
                            "key": "validation",
                            "name": (
                                "Validation Agent tracing reachability "
                                "& sandbox execution"
                            ),
                            "match": "validation_agent",
                        },
                        {
                            "key": "remediate",
                            "name": (
                                "Remediation Agent synthesizing safe "
                                "code patches"
                            ),
                            "match": "remediation_agent",
                        },
                        {
                            "key": "report",
                            "name": "Report Agent compiling report",
                            "match": "report_agent",
                        },
                    ]

                    active_index = 0
                    _ = time.time()
                    feedback_logs = set()
                    current_running_tool = None
                    validated_findings_count = 0
                    continuation_count = 0
                    max_continuations = 3

                    active_text_prompt = initial_prompt

                    TOOL_DISPLAY_MAP = {
                        "run_sandbox_command": (
                            "Verifying exploit inside sandbox"
                        ),
                        "read_code_window": (
                            "Analyzing code context & semantics"
                        ),
                        "grep_code": "Searching codebase for references",
                        "write_file_content": (
                            "Synthesizing unified code patches"
                        ),
                        "load_skill": "Loading expert playbooks",
                        "find_references": "Tracing symbol references",
                        "write_report": "Compiling Markdown report",
                        "semgrep": "Running Semgrep SAST engine",
                        "trivy": "Running Trivy SCA dependency checks",
                        "bandit": "Running Bandit Python scanner",
                        "gitleaks": "Scanning codebase for secrets",
                        "git": "Staging commits on PR branch",
                    }

                    while (
                        active_index < len(phases) - 1
                        and continuation_count < max_continuations
                    ):
                        if continuation_count > 0:
                            active_text_prompt = (
                                "[SYSTEM NOTICE: Output cutoff triggered by "
                                "maximum token limitations. Resume exactly "
                                "from where you left off. Synthesize "
                                "remaining patches or finish writing report.]"
                            )
                            _ = time.time()

                        payload = {
                            "app_name": "app",
                            "user_id": "cli-user",
                            "session_id": current_session_id,
                            "new_message": {
                                "role": "user",
                                "parts": [{"text": active_text_prompt}],
                            },
                        }

                        with requests.post(
                            run_url,
                            json=payload,
                            stream=True,
                            timeout=(60, None),
                        ) as resp:
                            if not resp.ok:
                                err_text = resp.text
                                raise RuntimeError(
                                    f"Failed to process scan cycle "
                                    f"(HTTP {resp.status_code}): {err_text}"
                                )

                            try:
                                for line in resp.iter_lines(
                                    decode_unicode=True
                                ):
                                    if not isinstance(
                                        line, str
                                    ) or not line.startswith("data: "):
                                        continue

                                    data_str = line[len("data: ") :]
                                    try:
                                        event = json.loads(data_str)
                                    except json.JSONDecodeError:
                                        continue

                                    event_str = json.dumps(event)
                                    parts = (
                                        event.get("content", {}).get(
                                            "parts", []
                                        )
                                        or event.get("parts", [])
                                        or []
                                    )

                                    found_tool = None
                                    if isinstance(event, dict):
                                        if (
                                            "function_call" in event
                                            and isinstance(
                                                event["function_call"], dict
                                            )
                                        ):
                                            found_tool = event[
                                                "function_call"
                                            ].get("name")
                                        elif (
                                            "functionCall" in event
                                            and isinstance(
                                                event["functionCall"], dict
                                            )
                                        ):
                                            found_tool = event[
                                                "functionCall"
                                            ].get("name")
                                        elif (
                                            "tool_calls" in event
                                            and event["tool_calls"]
                                        ):
                                            found_tool = event["tool_calls"][
                                                0
                                            ].get("function", {}).get(
                                                "name"
                                            ) or event[
                                                "tool_calls"
                                            ][
                                                0
                                            ].get(
                                                "name"
                                            )
                                        elif (
                                            "function_calls" in event
                                            and event["function_calls"]
                                        ):
                                            found_tool = event[
                                                "function_calls"
                                            ][0].get("name")
                                        elif (
                                            "running_tool" in event
                                            and isinstance(
                                                event["running_tool"], str
                                            )
                                        ):
                                            found_tool = event["running_tool"]

                                    if not found_tool:
                                        for p in parts:
                                            if isinstance(p, dict):
                                                fcall = (
                                                    p.get("function_call")
                                                    or p.get("functionCall")
                                                    or p.get("tool_call")
                                                )
                                                if fcall and isinstance(
                                                    fcall, dict
                                                ):
                                                    found_tool = fcall.get(
                                                        "name"
                                                    )
                                                    break

                                    if found_tool:
                                        current_running_tool = found_tool

                                    for p in parts:
                                        if isinstance(p, dict) and any(
                                            x in p
                                            for x in [
                                                "function_response",
                                                "functionResponse",
                                                "tool_response",
                                                "toolResponse",
                                            ]
                                        ):
                                            current_running_tool = None

                                    for p in parts:
                                        text = p.get("text", "")
                                        if text and isinstance(text, str):
                                            text_lower = text.lower()
                                            known_tools = [
                                                "semgrep",
                                                "gitleaks",
                                                "trivy",
                                                "bandit",
                                                "grep_code",
                                                "read_code_window",
                                                "find_references",
                                                "execute_in_sandbox",
                                            ]
                                            for kt in known_tools:
                                                if kt in text_lower:
                                                    current_running_tool = kt
                                                    break
                                            if (
                                                len(text) < 150
                                                and not text.startswith("{")
                                                and not current_running_tool
                                            ):
                                                text_clean = (
                                                    text.strip()
                                                    .replace("\n", " ")
                                                    .replace("`", "")
                                                )
                                                if any(
                                                    x in text_clean.lower()
                                                    for x in [
                                                        "auditing",
                                                        "checking",
                                                        "analyzing",
                                                        "scanning",
                                                        "reading",
                                                        "verifying",
                                                        "patching",
                                                        "looking",
                                                        "i will now",
                                                        "let's check",
                                                    ]
                                                ):
                                                    current_running_tool = (
                                                        text_clean[:55] + "..."
                                                        if len(text_clean) > 55
                                                        else text_clean
                                                    )

                                        if (
                                            "validated" in text.lower()
                                            and '"validated": true'
                                            in text.lower()
                                        ):
                                            try:
                                                cnt = _process_validated_event(
                                                    text,
                                                    feedback_logs,
                                                    console,
                                                )
                                                validated_findings_count += cnt
                                            except (
                                                ValueError,
                                                KeyError,
                                                TypeError,
                                            ) as e:
                                                logger.debug(
                                                    "Parse error: %s", e
                                                )

                                    if (
                                        "execute_in_sandbox" in event_str
                                        and "sandbox" not in feedback_logs
                                    ):
                                        console.print(
                                            "[bold cyan]↻[/] [dim]Validation "
                                            "Agent initiated container "
                                            "execution...[/]"
                                        )
                                        feedback_logs.add("sandbox")
                                    elif (
                                        "find_references" in event_str
                                        and "references" not in feedback_logs
                                    ):
                                        console.print(
                                            "[bold cyan]↻[/] [dim]Validation "
                                            "Agent initiated symbol reference "
                                            "tracing...[/]"
                                        )
                                        feedback_logs.add("references")

                                    author = event.get("author", "")
                                    for idx in range(
                                        active_index + 1, len(phases)
                                    ):
                                        p_info = phases[idx]
                                        matched = False
                                        if (
                                            p_info["key"] == "scanners"
                                            and p_info["match"] in event_str
                                        ):
                                            matched = True
                                        elif (
                                            p_info["match"]
                                            and p_info["match"] == author
                                        ):
                                            matched = True

                                        if matched:
                                            active_index = idx
                                            _ = time.time()
                                            current_running_tool = None
                                            break

                                    with lock:
                                        batch_states[batch_idx] = {
                                            "status": "running",
                                            "phase_name": phases[active_index][
                                                "name"
                                            ],
                                            "current_tool": (
                                                TOOL_DISPLAY_MAP.get(
                                                    current_running_tool,
                                                    current_running_tool,
                                                )
                                                if current_running_tool
                                                else ""
                                            ),
                                            "validated_findings": (
                                                validated_findings_count
                                            ),
                                            "elapsed": time.time()
                                            - batch_start_time,
                                        }
                            # Catching specific errors because SSE errors vary
                            except (
                                AttributeError,
                                KeyError,
                                OSError,
                                RuntimeError,
                                TypeError,
                                ValueError,
                            ) as e:
                                logger.debug(
                                    "SSE line exception in thread: %s", e
                                )
                                time.sleep(1.5)

                            with lock:
                                p_name = phases[active_index]["name"]
                                batch_states[batch_idx] = {
                                    "status": "running",
                                    "phase_name": p_name,
                                    "current_tool": "",
                                    "validated_findings": (
                                        validated_findings_count
                                    ),
                                    "elapsed": (time.time() - batch_start_time),
                                }

                        continuation_count += 1

                    with lock:
                        batch_states[batch_idx] = {
                            "status": "completed",
                            "phase_name": "Completed",
                            "current_tool": "",
                            "validated_findings": validated_findings_count,
                            "elapsed": time.time() - batch_start_time,
                        }
                    return current_session_id

                except Exception as e:  # pylint: disable=broad-exception-caught
                    # Catching Exception because parallel thread errors vary
                    logger.error(
                        "Error in parallel batch %s (Attempt %s): %s",
                        batch_idx + 1,
                        attempt + 1,
                        e,
                    )
                    if attempt < 2:
                        time.sleep(5.0)
                    else:
                        with lock:
                            batch_states[batch_idx] = {
                                "status": "failed",
                                "phase_name": f"Failed: {str(e)}",
                                "current_tool": "",
                                "validated_findings": (
                                    validated_findings_count
                                ),
                                "elapsed": time.time() - batch_start_time,
                            }
                        raise

        # Execute using ThreadPoolExecutor
        batch_session_ids = [None] * len(batches)
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=parallel_workers
        )
        try:
            with Live(
                render_progress_panel(), console=console, refresh_per_second=4
            ) as live:
                futures = {}
                for idx, batch in enumerate(batches):
                    f = executor.submit(execute_batch_parallel, idx, batch)
                    futures[f] = idx

                while futures:
                    done_futures, _ = concurrent.futures.wait(
                        futures.keys(),
                        timeout=0.25,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )

                    for f in done_futures:
                        idx = futures.pop(f)
                        try:
                            session_id = f.result()
                            batch_session_ids[idx] = session_id
                        except (
                            AttributeError,
                            KeyError,
                            OSError,
                            RuntimeError,
                            TypeError,
                            ValueError,
                        ):
                            # Catching specific errors for thread tasks
                            pass

                    live.update(render_progress_panel())
        except KeyboardInterrupt:
            executor.shutdown(wait=False, cancel_futures=True)
            console.print(
                "\n[bold red]⚠ Execution interrupted by user (Ctrl+C). "
                "Exiting immediately...[/]"
            )
            os._exit(1)  # pylint: disable=protected-access
        finally:
            executor.shutdown(wait=True)

        # Filter out failed runs (None values)
        batch_session_ids = [
            sid for sid in batch_session_ids if sid is not None
        ]

    else:
        # Fallback to exact serial logic originally implemented
        for batch_idx, batch in enumerate(batches):
            batch_success = False

            if batch_idx > 0:
                time.sleep(0.5)

            for attempt in range(3):
                try:
                    if len(batches) > 1:
                        if attempt == 0:
                            console.print(
                                "\n[bold cyan]↻ Executing Chunked Batch "
                                f"{batch_idx+1}/{len(batches)} "
                                f"({len(batch)} files)...[/]"
                            )
                        else:
                            console.print(
                                "\n[bold yellow]↻ Retrying Chunked Batch "
                                f"{batch_idx+1}/{len(batches)} "
                                f"(Attempt {attempt+1}/3)...[/]"
                            )

                    s_base = (
                        f"http://127.0.0.1:{port}/apps/app/"
                        "users/cli-user/sessions"
                    )
                    session_resp = requests.post(s_base, json={}, timeout=120)
                    if not session_resp.ok:
                        err_text = session_resp.text
                        raise RuntimeError(
                            f"Failed to create chunk session "
                            f"(HTTP {session_resp.status_code}): {err_text}"
                        )

                    current_session_id = session_resp.json().get("id")

                    if batch:
                        batch_paths = [os.path.abspath(p) for p in batch]
                        b_json = json.dumps(batch_paths)
                        initial_prompt = (
                            f"Scan {os.path.abspath(target_dir)} "
                            "focusing strictly on these codebase boundary "
                            f"files: {b_json}. Validate and remediate."
                        )
                    else:
                        initial_prompt = (
                            f"Scan {os.path.abspath(target_dir)} "
                            "for vulnerabilities and write a report."
                        )

                    phases = [
                        {
                            "key": "start",
                            "name": "Starting Reference Harness...",
                            "match": None,
                        },
                        {
                            "key": "scanners",
                            "name": (
                                "Executing static scanners "
                                "(Semgrep/Trivy/Gitleaks/Bandit)"
                            ),
                            "match": "scanner_allowlist",
                        },
                        {
                            "key": "llm_discovery",
                            "name": "Auditing codebase (AI playbooks)",
                            "match": "llm_discovery_agent",
                        },
                        {
                            "key": "triage",
                            "name": "Triage Critic filtering FPs",
                            "match": "triage_agent",
                        },
                        {
                            "key": "validation",
                            "name": (
                                "Validation Agent tracing reachability "
                                "& sandbox execution"
                            ),
                            "match": "validation_agent",
                        },
                        {
                            "key": "remediate",
                            "name": (
                                "Remediation Agent synthesizing safe "
                                "code patches"
                            ),
                            "match": "remediation_agent",
                        },
                        {
                            "key": "report",
                            "name": "Report Agent compiling report",
                            "match": "report_agent",
                        },
                    ]

                    active_index = 0
                    _phase_start = time.time()
                    feedback_logs = set()
                    current_running_tool = None
                    validated_findings_count = 0
                    continuation_count = 0
                    max_continuations = 3

                    active_text_prompt = initial_prompt

                    while (
                        active_index < len(phases) - 1
                        and continuation_count < max_continuations
                    ):
                        if continuation_count > 0:
                            active_text_prompt = (
                                "[SYSTEM NOTICE: Output cutoff triggered by "
                                "maximum token limitations. Resume exactly "
                                "from where you left off. Synthesize "
                                "remaining patches or finish writing report.]"
                            )
                            _phase_start = time.time()

                        payload = {
                            "app_name": "app",
                            "user_id": "cli-user",
                            "session_id": current_session_id,
                            "new_message": {
                                "role": "user",
                                "parts": [{"text": active_text_prompt}],
                            },
                        }

                        with requests.post(
                            run_url,
                            json=payload,
                            stream=True,
                            timeout=(60, None),
                        ) as resp:
                            if not resp.ok:
                                err_text = resp.text
                                raise RuntimeError(
                                    f"Failed to process scan cycle "
                                    f"(HTTP {resp.status_code}): {err_text}"
                                )

                            with Live(
                                get_active_line_text(
                                    phases[active_index]["name"],
                                    _phase_start,
                                    current_running_tool,
                                    validated_findings_count,
                                ),
                                refresh_per_second=10,
                            ) as live:
                                try:
                                    for line in resp.iter_lines(
                                        decode_unicode=True
                                    ):
                                        if not isinstance(
                                            line, str
                                        ) or not line.startswith("data: "):
                                            continue

                                        data_str = line[len("data: ") :]
                                        try:
                                            event = json.loads(data_str)
                                        except json.JSONDecodeError:
                                            continue

                                        event_str = json.dumps(event)
                                        parts = (
                                            event.get("content", {}).get(
                                                "parts", []
                                            )
                                            or event.get("parts", [])
                                            or []
                                        )

                                        found_tool = None
                                        if isinstance(event, dict):
                                            if (
                                                "function_call" in event
                                                and isinstance(
                                                    event["function_call"], dict
                                                )
                                            ):
                                                found_tool = event[
                                                    "function_call"
                                                ].get("name")
                                            elif (
                                                "functionCall" in event
                                                and isinstance(
                                                    event["functionCall"], dict
                                                )
                                            ):
                                                found_tool = event[
                                                    "functionCall"
                                                ].get("name")
                                            elif (
                                                "tool_calls" in event
                                                and event["tool_calls"]
                                            ):
                                                found_tool = event[
                                                    "tool_calls"
                                                ][0].get("function", {}).get(
                                                    "name"
                                                ) or event[
                                                    "tool_calls"
                                                ][
                                                    0
                                                ].get(
                                                    "name"
                                                )
                                            elif (
                                                "function_calls" in event
                                                and event["function_calls"]
                                            ):
                                                found_tool = event[
                                                    "function_calls"
                                                ][0].get("name")
                                            elif (
                                                "running_tool" in event
                                                and isinstance(
                                                    event["running_tool"], str
                                                )
                                            ):
                                                found_tool = event[
                                                    "running_tool"
                                                ]

                                        if not found_tool:
                                            for p in parts:
                                                if isinstance(p, dict):
                                                    fcall = (
                                                        p.get("function_call")
                                                        or p.get("functionCall")
                                                        or p.get("tool_call")
                                                    )
                                                    if fcall and isinstance(
                                                        fcall, dict
                                                    ):
                                                        found_tool = fcall.get(
                                                            "name"
                                                        )
                                                        break

                                        if found_tool:
                                            current_running_tool = found_tool

                                        for p in parts:
                                            if isinstance(p, dict) and any(
                                                x in p
                                                for x in [
                                                    "function_response",
                                                    "functionResponse",
                                                    "tool_response",
                                                    "toolResponse",
                                                ]
                                            ):
                                                current_running_tool = None

                                        for p in parts:
                                            text = p.get("text", "")
                                            if text and isinstance(text, str):
                                                text_lower = text.lower()
                                                known_tools = [
                                                    "semgrep",
                                                    "gitleaks",
                                                    "trivy",
                                                    "bandit",
                                                    "grep_code",
                                                    "read_code_window",
                                                    "find_references",
                                                    "execute_in_sandbox",
                                                ]
                                                for kt in known_tools:
                                                    if kt in text_lower:
                                                        current_running_tool = (
                                                            kt
                                                        )
                                                        break
                                                if (
                                                    len(text) < 150
                                                    and not text.startswith("{")
                                                    and not current_running_tool
                                                ):
                                                    text_clean = (
                                                        text.strip()
                                                        .replace("\n", " ")
                                                        .replace("`", "")
                                                    )
                                                    if any(
                                                        x in text_clean.lower()
                                                        for x in [
                                                            "auditing",
                                                            "checking",
                                                            "analyzing",
                                                            "scanning",
                                                            "reading",
                                                            "verifying",
                                                            "patching",
                                                            "looking",
                                                            "i will now",
                                                            "let's check",
                                                        ]
                                                    ):
                                                        current_running_tool = (
                                                            text_clean[:55]
                                                            + "..."
                                                            if len(text_clean)
                                                            > 55
                                                            else text_clean
                                                        )

                                                val_cnt = _update_cnt(
                                                    validated_findings_count,
                                                    text,
                                                    feedback_logs,
                                                    live.console,
                                                )
                                                validated_findings_count = (
                                                    val_cnt
                                                )
                                        if (
                                            "execute_in_sandbox" in event_str
                                            and "sandbox" not in feedback_logs
                                        ):
                                            live.console.print(
                                                "[bold cyan]↻[/] "
                                                "[dim]Validation Agent "
                                                "initiated container "
                                                "execution...[/]"
                                            )
                                            feedback_logs.add("sandbox")
                                        elif (
                                            "find_references" in event_str
                                            and "references"
                                            not in feedback_logs
                                        ):
                                            live.console.print(
                                                "[bold cyan]↻[/] "
                                                "[dim]Validation Agent "
                                                "initiated symbol reference "
                                                "tracing...[/]"
                                            )
                                            feedback_logs.add("references")

                                        author = event.get("author", "")
                                        for idx in range(
                                            active_index + 1, len(phases)
                                        ):
                                            p_info = phases[idx]
                                            matched = False
                                            if (
                                                p_info["key"] == "scanners"
                                                and p_info["match"] in event_str
                                            ):
                                                matched = True
                                            elif (
                                                p_info["match"]
                                                and p_info["match"] == author
                                            ):
                                                matched = True

                                            if matched:
                                                prev_elapsed = (
                                                    time.time() - _phase_start
                                                )
                                                p_name = phases[active_index][
                                                    "name"
                                                ]
                                                live.console.print(
                                                    f"[bold green]✓[/] "
                                                    f"{p_name} [dim]("
                                                    f"{prev_elapsed:.1f}s)[/]"
                                                )
                                                active_index = idx
                                                _phase_start = time.time()
                                                current_running_tool = None
                                                u_args = (
                                                    phases[active_index][
                                                        "name"
                                                    ],
                                                    _phase_start,
                                                    current_running_tool,
                                                    validated_findings_count,
                                                )
                                                live.update(
                                                    get_active_line_text(
                                                        *u_args
                                                    )
                                                )
                                                break

                                        live.update(
                                            get_active_line_text(
                                                phases[active_index]["name"],
                                                _phase_start,
                                                current_running_tool,
                                                validated_findings_count,
                                            )
                                        )
                                except (
                                    ValueError,
                                    KeyError,
                                    TypeError,
                                    OSError,
                                    RuntimeError,
                                ) as e:
                                    logger.debug(
                                        "SSE line processing exception: %s", e
                                    )
                                    live.console.print(
                                        "[bold yellow]↻[/] [dim]Context border "
                                        "reached. Processing continuation...[/]"
                                    )
                                    time.sleep(1.5)

                                last_elapsed = time.time() - _phase_start
                                p_name = phases[active_index]["name"]
                                live.update(
                                    f"[bold green]✓[/] {p_name} [dim]("
                                    f"{last_elapsed:.1f}s)[/]"
                                )

                        continuation_count += 1

                    batch_session_ids.append(current_session_id)
                    batch_success = True
                    break

                except Exception as e:  # pylint: disable=broad-exception-caught
                    # Catching Exception because batch cycle errors vary
                    logger.error(
                        "Error executing chunked batch %s: %s",
                        batch_idx + 1,
                        e,
                    )
                    if attempt < 2:
                        console.print(
                            f"[bold red]⚠ Network interrupt during Batch "
                            f"{batch_idx+1}: {str(e)}. Retrying in 5s...[/]"
                        )
                        time.sleep(5.0)
                    else:
                        raise e

            if not batch_success:
                break

        server_manager.stop_adk_server()

    gcs_bucket = args.gcs_bucket
    if gcs_bucket:
        gcs_bucket = gcs_bucket.strip("“\"'”‘’")

    gcs_prefix = args.gcs_prefix
    if gcs_prefix:
        gcs_prefix = gcs_prefix.strip("“\"'”‘’")

    compile_and_render_results(
        start_time=start_time,
        target_dir=target_dir,
        batch_session_ids=batch_session_ids,
        flash_model=flash_model,
        output_format=args.output_format,
        gcs_bucket=gcs_bucket,
        gcs_prefix=gcs_prefix,
    )


def entry_point():
    try:
        main()
    except KeyboardInterrupt:
        console = Console()
        console.print(
            "\n[bold red]⚠ Scan interrupted by user (Ctrl+C). "
            "Cleaning up and exiting...[/]"
        )
        try:
            # Force cleanup the agents background server
            subprocess.run(
                ["agents-cli", "run", "--stop-server"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            pass
        os._exit(1)  # pylint: disable=protected-access
    except Exception as e:  # pylint: disable=broad-exception-caught
        # Catching Exception at entry point to log and display fatal errors
        logger.exception(
            "Reference Harness execution failed due to unhandled exception"
        )
        try:
            # Force cleanup the agents background server
            subprocess.run(
                ["agents-cli", "run", "--stop-server"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            pass

        console = Console()

        console.print("\n[bold red]✗ Scan Failed[/]")
        err_str = str(e)
        if (
            "Read timed out" in err_str
            or "ConnectionError" in err_str
            or "TimeoutError" in err_str
        ):
            console.print(
                Panel(
                    "[bold red]✗ Connection Timeout Alert[/]\n\n"
                    "Vertex AI gateway timed out (>120s) under load.\n"
                    "Your previous scan results are cached in background.\n\n"
                    "🚀 [bold cyan]Re-run scan command to resolve from "
                    "cache![/]",
                    border_style="red",
                    title="[bold red]Vertex AI Timeout[/]",
                )
            )
        else:
            console.print(f"[bold red]✗ Error:[/] {err_str}")
        sys.exit(1)


if __name__ == "__main__":
    entry_point()
