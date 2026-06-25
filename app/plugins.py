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
"""Defense-in-depth plugin: blocks tool calls outside the VulnCatcher
allowlist."""

from typing import Any

from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools import ToolContext
from google.adk.tools.base_tool import BaseTool

ALLOWED_TOOLS = frozenset(
    {
        "detect_languages",
        "run_semgrep",
        "run_trivy",
        "run_gitleaks",
        "run_bandit",
        "list_dir",
        "grep_code",
        "read_code_window",
        "load_skill",
        "find_references",
        "query_ast",
        "execute_in_sandbox",
        "map_boundaries",
        "write_report",
    }
)


class ScannerAllowlistPlugin(BasePlugin):
    """Blocks any tool whose name is not in the VulnCatcher allowlist.

    Rationale: the agent is only configured with these tools today, but a
    future refactor or sub-agent that picks up extra tools (built-ins, MCP,
    etc.) should not silently widen the attack surface.
    """

    def __init__(self) -> None:
        super().__init__(name="scanner_allowlist")

    async def before_tool_callback(
        self,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        del tool_args, tool_context
        if tool.name not in ALLOWED_TOOLS:
            return {
                "status": "blocked",
                "error": (
                    f"Tool {tool.name!r} is not in the VulnCatcher allowlist. "
                    f"Allowed: {sorted(ALLOWED_TOOLS)}."
                ),
            }
        return None
