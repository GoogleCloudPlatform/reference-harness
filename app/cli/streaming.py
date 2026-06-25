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

"""Streaming text formatting utilities."""

import time


def get_active_line_text(
    phase_name, start_time, running_tool=None, findings_count=0
):
    elapsed = time.time() - start_time

    # Premium Human-Friendly Display translation mapping (Polished DX)
    TOOL_DISPLAY_MAP = {
        "run_sandbox_command": "Verifying exploit inside secure sandbox",
        "read_code_window": "Analyzing code context & semantics",
        "grep_code": "Searching codebase for references",
        "write_file_content": "Synthesizing unified code patches",
        "load_skill": "Loading expert vulnerability playbooks",
        "find_references": "Tracing symbol cross-references",
        "write_report": "Compiling Markdown audit report",
        "semgrep": "Running Semgrep SAST engine",
        "trivy": "Running Trivy SCA dependency checks",
        "bandit": "Running Bandit Python scanner",
        "gitleaks": "Scanning codebase for secrets",
        "git": "Staging commits on PR branch",
    }

    display_tool = (
        TOOL_DISPLAY_MAP.get(running_tool, running_tool)
        if running_tool
        else None
    )
    tool_tag = (
        f" [bold yellow][running: {display_tool}][/]" if display_tool else ""
    )
    findings_tag = (
        f" [bold red][{findings_count} validated][/]"
        if findings_count > 0
        else ""
    )
    return (
        f"[bold yellow]▰▰▰[/] {phase_name} [dim]({elapsed:.1f}s)[/]"
        f"{tool_tag}{findings_tag}"
    )
