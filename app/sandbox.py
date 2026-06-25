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

"""Sandbox runtime execution utilities."""

import os
import shutil
import subprocess
import sys
import tempfile
import time

from rich.console import Console
from rich.panel import Panel


def execute_in_sandbox(
    code_content: str, payload_content: str, language: str = "javascript"
) -> dict:
    """Execute suspect code inside secure runtime with configurable isolation.

    Environment Configurations:
        VULNCATCHER_SANDBOX_MODE: docker (default)|native|local|static
        VULNCATCHER_SANDBOX_FALLBACK: "auto" (default) | "fail"

    Returns:
        dict with 'status', 'exit_code', 'stdout', 'stderr', 'duration',
        'mode_used'.
    """
    console = Console()

    # Read user configurations from shell environment variables
    selected_mode = os.environ.get("VULNCATCHER_SANDBOX_MODE", "docker").lower()
    fallback_policy = os.environ.get(
        "VULNCATCHER_SANDBOX_FALLBACK", "auto"
    ).lower()

    supported_modes = ["docker", "native", "local", "static"]
    if selected_mode not in supported_modes:
        selected_mode = "docker"

    return _run_with_mode(
        code_content,
        payload_content,
        language,
        selected_mode,
        fallback_policy,
        console,
    )


def _run_with_mode(
    code_content: str,
    payload_content: str,
    language: str,
    mode: str,
    fallback: str,
    console: Console,
) -> dict:
    if mode == "static":
        return {
            "status": "skipped",
            "reason": "Static-only checks; dynamic validation bypassed.",
            "mode_used": "static",
        }

    if mode == "docker":
        res = _run_docker(code_content, payload_content, language)
        if res["status"] != "error" or fallback == "fail":
            return res
        # Fallback cascade
        console.print(
            "[bold yellow]⚠️ Sandbox Warning:[/] Docker execution failed "
            "or is not installed. Cascading fallback to 'native' OS sandboxing."
        )
        return _run_with_mode(
            code_content, payload_content, language, "native", fallback, console
        )

    if mode == "native":
        res = _run_native_os(code_content, payload_content, language)
        if res["status"] != "error" or fallback == "fail":
            return res
        # Fallback cascade
        console.print(
            "[bold yellow]⚠️ Sandbox Warning:[/] Native OS sandboxing failed. "
            "Cascading fallback to 'local' host execution."
        )
        return _run_with_mode(
            code_content, payload_content, language, "local", fallback, console
        )

    if mode == "local":
        # Print a highly visible warnings panel to alert developers
        console.print(
            Panel(
                "[bold red]⚠️ WARNING: DIRECT HOST EXECUTION[/]\n"
                "Docker and Native OS sandboxing are disabled.\n"
                "Exploit validation scripts will run on your host.\n"
                "Proceed with caution if scanning untrusted codebases.",
                border_style="red",
                title="[bold red]Sandbox Isolation Alert[/]",
            )
        )
        res = _run_local_host(code_content, payload_content, language)
        if res["status"] != "error" or fallback == "fail":
            return res

        # Absolute bottom of the cascade: fallback to static
        console.print(
            "[bold red]✗ Sandbox Error:[/] Local execution failed. "
            "Downgrading to 'static' triage."
        )
        return _run_with_mode(
            code_content, payload_content, language, "static", fallback, console
        )

    return {
        "status": "error",
        "error": f"Invalid sandbox execution mode: {mode}",
    }


def _run_docker(code_content: str, payload_content: str, language: str) -> dict:
    temp_dir = tempfile.mkdtemp()

    try:
        if language == "javascript":
            target_filename = "target.js"
            payload_filename = "payload.js"
            image_name = "node:18-alpine"
            run_cmd = ["node", payload_filename]
        elif language == "python":
            target_filename = "target.py"
            payload_filename = "payload.py"
            image_name = "python:3.10-alpine"
            run_cmd = ["python", payload_filename]
        elif language in ("bash", "shell"):
            target_filename = "target.sh"
            payload_filename = "payload.sh"
            image_name = "alpine"
            run_cmd = ["sh", payload_filename]
        else:
            return {
                "status": "error",
                "error": f"Unsupported runtime: {language}",
            }

        with open(
            os.path.join(temp_dir, target_filename), "w", encoding="utf-8"
        ) as f:
            f.write(code_content)
        with open(
            os.path.join(temp_dir, payload_filename), "w", encoding="utf-8"
        ) as f:
            f.write(payload_content)

        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-u",
            "1000:1000",
            "--read-only",
            "--tmpfs",
            "/tmp:size=64m",
            "--memory=256m",
            "--cpus=0.5",
            "--pids-limit=50",
            "-v",
            f"{temp_dir}:/app:ro",
            "-w",
            "/app",
            image_name,
        ] + run_cmd

        start_time = time.time()
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0,
            check=False,
        )
        duration = time.time() - start_time

        return {
            "status": "success",
            "exit_code": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
            "duration": duration,
            "mode_used": "docker",
        }
    except (subprocess.SubprocessError, OSError) as e:
        return {"status": "error", "error": str(e)}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _run_native_os(
    code_content: str, payload_content: str, language: str
) -> dict:
    temp_dir = tempfile.mkdtemp()

    try:
        if language == "javascript":
            target_filename = "target.js"
            payload_filename = "payload.js"
            run_cmd = ["node", payload_filename]
        elif language == "python":
            target_filename = "target.py"
            payload_filename = "payload.py"
            run_cmd = [sys.executable, payload_filename]
        elif language in ("bash", "shell"):
            target_filename = "target.sh"
            payload_filename = "payload.sh"
            run_cmd = ["sh", payload_filename]
        else:
            return {
                "status": "error",
                "error": f"Unsupported runtime: {language}",
            }

        with open(
            os.path.join(temp_dir, target_filename), "w", encoding="utf-8"
        ) as f:
            f.write(code_content)
        with open(
            os.path.join(temp_dir, payload_filename), "w", encoding="utf-8"
        ) as f:
            f.write(payload_content)

        # Check for macOS native kernel sandbox profile
        if sys.platform == "darwin":
            # sandbox-exec: allow default, restrict network and file write
            sandbox_profile = (
                "(version 1)"
                "(allow default)"
                "(deny network-outbound)"
                f'(deny file-write* (require-not (subpath "{temp_dir}"))'
                '(require-not (subpath "/dev")))'
            )
            command = [
                "sandbox-exec",
                "-p",
                sandbox_profile,
            ] + run_cmd
        else:
            # Fallback to Linux standard namespaces if firejail is installed
            if shutil.which("firejail"):
                command = ["firejail", "--net=none", "--quiet"] + run_cmd
            else:
                return {
                    "status": "error",
                    "error": (
                        "No native OS sandboxing tool "
                        "(sandbox-exec / firejail) detected."
                    ),
                }

        start_time = time.time()
        process = subprocess.run(
            command,
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0,
            check=False,
        )
        duration = time.time() - start_time

        return {
            "status": "success",
            "exit_code": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
            "duration": duration,
            "mode_used": "native",
        }
    except (subprocess.SubprocessError, OSError) as e:
        return {"status": "error", "error": str(e)}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _run_local_host(
    code_content: str, payload_content: str, language: str
) -> dict:
    # Local execution directly runs target code on the developer's host
    temp_dir = tempfile.mkdtemp()

    try:
        if language == "javascript":
            target_filename = "target.js"
            payload_filename = "payload.js"
            run_cmd = ["node", payload_filename]
        elif language == "python":
            target_filename = "target.py"
            payload_filename = "payload.py"
            run_cmd = [sys.executable, payload_filename]
        elif language in ("bash", "shell"):
            target_filename = "target.sh"
            payload_filename = "payload.sh"
            run_cmd = ["sh", payload_filename]
        else:
            return {
                "status": "error",
                "error": f"Unsupported runtime: {language}",
            }

        with open(
            os.path.join(temp_dir, target_filename), "w", encoding="utf-8"
        ) as f:
            f.write(code_content)
        with open(
            os.path.join(temp_dir, payload_filename), "w", encoding="utf-8"
        ) as f:
            f.write(payload_content)

        start_time = time.time()
        process = subprocess.run(
            run_cmd,
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0,
            check=False,
        )
        duration = time.time() - start_time

        return {
            "status": "success",
            "exit_code": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
            "duration": duration,
            "mode_used": "local",
        }
    except (subprocess.SubprocessError, OSError) as e:
        return {"status": "error", "error": str(e)}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
