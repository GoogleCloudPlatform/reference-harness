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
    return f"[bold yellow]▰▰▰[/] {phase_name} [dim]({elapsed:.1f}s)[/]{tool_tag}{findings_tag}"
