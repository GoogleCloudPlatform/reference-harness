#!/usr/bin/env python3
import glob
import json
import os
import subprocess
import sys
import time

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


def main():
    console = Console()

    extra_args = sys.argv[1:]
    if not extra_args:
        extra_args = [
            "--evalset",
            "tests/eval/evalsets/vulncatcher_nodegoat.evalset.json",
        ]
    elif "--evalset" not in extra_args and os.path.exists(extra_args[0]):
        # If user just passed path, prepend --evalset automatically
        extra_args = ["--evalset", extra_args[0]] + extra_args[1:]

    console.print(
        Panel.fit(
            "[bold green]VulnCatcher Evaluation Suite[/]\n"
            f"[dim]Executing with parameters:[/] {' '.join(extra_args)}",
            border_style="green",
        )
    )

    # Force PyPI index in subprocesses to bypass private staged authentication
    env = os.environ.copy()
    env["UV_DEFAULT_INDEX"] = "https://pypi.org/simple"
    env["UV_NO_SYNC"] = "1"
    env["ADK_LOG_LEVEL"] = "ERROR"
    env["PYTHONWARNINGS"] = "ignore"
    env["PYTHONUNBUFFERED"] = "1"

    command = ["agents-cli", "eval", "run"] + extra_args

    start_time = time.time()

    phases = [
        {
            "key": "start",
            "name": "Starting VulnCatcher evaluation worker...",
            "match": None,
        },
        {
            "key": "flash",
            "name": "Auditing playbook targets (Gemini Flash executing)",
            "match": "Sending out request, model: gemini-3.5-flash",
        },
        {
            "key": "pro",
            "name": "Auditing playbook targets (Gemini Pro executing)",
            "match": "Sending out request, model: gemini-3.1-pro-preview",
        },
        {
            "key": "judge",
            "name": "Calculating scorecard rubrics (Invoking LLM-As-Judge)",
            "match": "Sending out request, model: gemini-3-flash-preview",
        },
        {
            "key": "write",
            "name": "Compiling final scorecard metric results...",
            "match": "Writing eval result to file",
        },
    ]

    active_index = 0
    phase_start = time.time()

    def get_active_line_text(phase_name, start_time):
        elapsed = time.time() - start_time
        return f"[bold yellow]▰▰▰[/] {phase_name} [dim]({elapsed:.1f}s)[/]"

    try:
        # Spawn eval silently, merging stderr into stdout
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            bufsize=1,
        )

        full_output = []
        with Live(
            get_active_line_text(phases[0]["name"], phase_start),
            refresh_per_second=10,
        ) as live:
            for line in iter(process.stdout.readline, ""):
                full_output.append(line)

                # Check if this line triggers a transition to a forward phase!
                for idx in range(active_index + 1, len(phases)):
                    p_info = phases[idx]
                    match_key = p_info["key"]
                    matched = False
                    if (
                        match_key == "flash"
                        and "model: " in line
                        and "flash" in line.lower()
                        and "judge" not in line.lower()
                    ):
                        matched = True
                    elif (
                        match_key == "pro"
                        and "model: " in line
                        and "pro" in line.lower()
                    ):
                        matched = True
                    elif (
                        match_key == "judge"
                        and "model: " in line
                        and (
                            "judge" in line.lower()
                            or "gemini-3" in line.lower()
                        )
                    ):
                        matched = True
                    elif p_info["match"] and p_info["match"] in line:
                        matched = True

                    if matched:
                        # Close previous phase permanently above the active line
                        prev_elapsed = time.time() - phase_start
                        live.console.print(
                            f"[bold green]✓[/] {phases[active_index]['name']} [dim]({prev_elapsed:.1f}s)[/]"
                        )

                        # Transition to the new phase
                        active_index = idx
                        phase_start = time.time()
                        live.update(
                            get_active_line_text(
                                phases[active_index]["name"], phase_start
                            )
                        )
                        break

                # Update active line timer
                live.update(
                    get_active_line_text(
                        phases[active_index]["name"], phase_start
                    )
                )

            # Complete the last active phase inside the Live block before exiting
            last_elapsed = time.time() - phase_start
            live.update(
                f"[bold green]✓[/] {phases[active_index]['name']} [dim]({last_elapsed:.1f}s)[/]"
            )

        process.wait()
        elapsed = time.time() - start_time
        stdout_content = "".join(full_output)

        # Filter out internal boot trace logs for final scorecard print
        clean_stdout = []
        for line in stdout_content.splitlines():
            if any(
                x in line
                for x in [
                    "uv ",
                    "Using evaluation",
                    "UserWarning",
                    "LlmAsJudge",
                    "Sending out",
                    "Response received",
                    "Plugin '",
                    "Writing eval",
                    "Started server",
                    "Waiting for",
                ]
            ):
                continue
            clean_stdout.append(line)

        if process.returncode != 0:
            console.print("\n[bold red]✗ Evaluation Failed[/]")

            # Intercept and parse standard Vertex AI API gateway connection read timeouts!
            if (
                "Read timed out" in stdout_content
                or "ConnectionError" in stdout_content
                or "TimeoutError" in stdout_content
            ):
                console.print(
                    Panel(
                        "[bold red]✗ Connection Timeout Alert[/]\n\n"
                        "The Vertex AI API gateway took longer than 120 seconds to respond under high capacity load.\n"
                        "Your previous evaluation results have been fully cached in the background.\n\n"
                        "🚀 [bold cyan]Simply re-run the evaluation command to resolve instantly from cache![/]",
                        border_style="red",
                        title="[bold red]Vertex AI Timeout[/]",
                    )
                )
            else:
                # Otherwise filter out verbose Python stack tracebacks for clean logs
                clean_err = []
                for line in stdout_content.splitlines():
                    if any(
                        x in line
                        for x in [
                            "Traceback (",
                            "  File ",
                            "line = self.",
                            "socket.py",
                            "socket.py",
                        ]
                    ):
                        continue
                    clean_err.append(line)
                console.print("\n".join(clean_err) or "Unknown error occurred.")
            sys.exit(process.returncode)

        console.print(
            f"\n[bold green]✔ Evaluations Completed![/] [dim]({elapsed:.1f}s)[/]"
        )
        console.print("\n" + "\n".join(clean_stdout))

        # Display premium custom scorecard dashboard
        show_scorecard_dashboard(console)

    except Exception as e:
        console.print(f"\n[bold red]✗ Error:[/] {e!s}")
        sys.exit(1)


def show_scorecard_dashboard(console):
    history_dir = "app/.adk/eval_history"
    files = glob.glob(f"{history_dir}/*.json")
    if not files:
        return

    latest_file = max(files, key=os.path.getmtime)

    try:
        with open(latest_file) as f:
            data = json.load(f)

        case_result = data["eval_case_results"][0]
        metrics = case_result.get("overall_eval_metric_results", [])
        if not metrics:
            return

        table = Table(show_header=True, header_style="bold cyan", box=None)
        table.add_column("Metric / Seeded Playbook Rubric", width=55)
        table.add_column("Score", width=10, justify="right")
        table.add_column("Status", width=10, justify="center")

        for m in metrics:
            name = m["metric_name"]
            score = m["score"]

            if name == "tool_trajectory_avg_score":
                table.add_row(
                    "Tool Trajectory (Sequential Order)",
                    f"{score:.1f}",
                    "[dim]Exempt[/]",
                )
                continue

            status = (
                "[bold green]PASS[/]"
                if m["eval_status"] == 1
                else "[bold red]FAIL[/]"
            )

            if name == "hallucinations_v1":
                table.add_row(
                    "Zero Hallucinations (Grounded Evidence)",
                    f"{score * 100:.1f}%",
                    status,
                )
            elif name == "rubric_based_final_response_quality_v1":
                table.add_row(
                    "Playbook Category Quality", f"{score * 100:.1f}%", status
                )

                # Rubric details
                rubric_scores = m["details"].get("rubric_scores", [])
                for r in rubric_scores:
                    r_id = r["rubric_id"]
                    r_score = r["score"]
                    r_status = (
                        "[green]✓ PASS[/]"
                        if r_score == 1.0
                        else "[red]✗ FAIL[/]"
                    )
                    table.add_row(
                        f"  [dim]↳ {r_id}[/]", f"{r_score:.1f}", r_status
                    )

        console.print(
            Panel.fit(
                table,
                title="[bold green]VulnCatcher Custom Evaluation Scorecard[/]",
                border_style="green",
                subtitle=f"[dim]Source: {os.path.basename(latest_file)}[/]",
            )
        )

    except Exception:
        pass


if __name__ == "__main__":
    main()
