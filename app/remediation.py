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

"""Security remediation and Git patching utilities."""

import os
import subprocess


def apply_patch(file_path: str, diff_content: str) -> dict:
    """Apply a Unified Git Diff patch directly to a target file.

    Uses the standard patch utility.

    Args:
        file_path: The path to the target file to patch.
        diff_content: The verbatim Unified Git Diff string.

    Returns:
        dict with 'status', 'stdout', 'stderr', and 'exit_code'.
    """
    if not os.path.exists(file_path):
        return {
            "status": "error",
            "error": f"Target file not found: {file_path}",
        }

    # Shell-out safely to the native patch utility.
    # Standard patch reads the unified diff from stdin.
    # Pass '-t' (batch) and '-N' (forward) flags to suppress all interactive
    # prompts.
    command = ["patch", "-t", "-N", file_path]

    try:
        process = subprocess.run(
            command,
            input=diff_content,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5.0,
            check=False,
        )

        if process.returncode == 0:
            return {
                "status": "success",
                "exit_code": 0,
                "stdout": process.stdout,
                "stderr": process.stderr,
            }
        else:
            return {
                "status": "error",
                "exit_code": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
                "error": (
                    "Failed to apply git diff patch using the local patch "
                    "utility."
                ),
            }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Patch application timed out after 5 seconds.",
        }
    except OSError as e:
        return {
            "status": "error",
            "error": f"Patch application execution failure: {e!s}",
        }


def create_remediation_branch(
    file_path: str, diff_content: str, branch_name: str
) -> dict:
    """Spawn a new Git branch, apply security patch, and commit fix safely.

    Args:
        file_path: The path to the file being patched.
        diff_content: The verbatim Unified Git Diff string.
        branch_name: The high-entropy branch name to create.

    Returns:
        dict with 'status', 'branch', and 'commit_hash'.
    """
    # Verify Git is initialized
    if not os.path.exists(".git"):
        return {
            "status": "error",
            "error": "Git repository not found in the current workspace.",
        }

    try:
        # 1. Checkout a new branch safely
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # 2. Apply the patch using the local patch utility
        patch_res = apply_patch(file_path, diff_content)
        if patch_res["status"] != "success":
            # Revert checkout if patch fails
            subprocess.run(
                ["git", "checkout", "-"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                ["git", "branch", "-D", branch_name],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return patch_res

        # 3. Stage modified file (force stage with -f for ignored files)
        subprocess.run(
            ["git", "add", "-f", file_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # 4. Commit the patch
        base = os.path.basename(file_path)
        commit_msg = (
            f"Sec: Automatically resolve security vulnerability in {base}"
        )
        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # 5. Retrieve the commit hash
        process = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        commit_hash = process.stdout.strip()

        return {
            "status": "success",
            "branch": branch_name,
            "commit_hash": commit_hash,
        }

    except subprocess.CalledProcessError as e:
        # Gracefully clean up and attempt to switch back to original branch
        subprocess.run(
            ["git", "checkout", "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return {
            "status": "error",
            "error": (
                "Git operation failure: "
                f"{e.stderr.strip() if e.stderr else str(e)}"
            ),
        }
