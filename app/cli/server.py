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

"""ADK background server management CLI."""

import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

from rich.console import Console


class ADKServerManager:
    """Manages ADK server lifecycle."""

    def __init__(self):
        self.active_server_process = None
        self.active_server_port = 18080
        self.console = Console()

    def force_kill_port(self, target_port=None):
        if target_port is None:
            target_port = self.active_server_port
        try:
            port_proc = subprocess.run(
                f"lsof -n -P -t -iTCP:{target_port} -sTCP:LISTEN 2>/dev/null",
                shell=True,
                stdout=subprocess.PIPE,
                text=True,
                check=False,
            )
            pids = port_proc.stdout.strip().split()

            my_pid = str(os.getpid())

            for pid in pids:
                if pid and pid != my_pid:
                    subprocess.run(
                        ["kill", "-9", pid],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
        except (OSError, subprocess.SubprocessError):
            pass

    def start_adk_server(self, env_map):
        log_path = str(
            Path(__file__).parent.parent / ".adk" / "uvicorn_boot.log"
        )
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        for attempt in range(3):
            self.console.print(
                "[bold yellow]↻ Spinning up local background ADK server "
                f"(Attempt {attempt+1}/3)...[/]"
            )
            self.force_kill_port(18080)
            if self.active_server_port != 18080:
                self.force_kill_port(self.active_server_port)
            time.sleep(1.5)

            # Open in write mode ("w") to truncate historical logs
            boot_log = open(log_path, "w", encoding="utf-8")
            boot_log.write(f"\n--- ADK Server Boot Attempt {attempt+1} ---\n")
            boot_log.flush()

            if getattr(sys, "frozen", False):
                cmd = [
                    sys.executable,
                    "api_server",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "18080",
                    str(Path(__file__).parent.parent.parent),
                ]
                env_map["VULNCATCHER_ADK_SERVER_MODE"] = "1"
            else:
                python_bin_dir = os.path.dirname(sys.executable)
                adk_bin = os.path.join(python_bin_dir, "adk")
                if not os.path.exists(adk_bin):
                    adk_bin = "adk"
                cmd = [
                    adk_bin,
                    "api_server",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "18080",
                    "--reload",
                    str(Path(__file__).parent.parent.parent),
                ]

            server_proc = subprocess.Popen(
                cmd, stdout=boot_log, stderr=boot_log, env=env_map
            )
            self.active_server_process = server_proc

            allocated_port = None
            for _ in range(240):  # 60s max timeout under QEMU/emulation
                time.sleep(0.25)
                if server_proc.poll() is not None:
                    break
                if os.path.exists(log_path):
                    try:
                        with open(log_path, "r", encoding="utf-8") as lf:
                            content = lf.read()
                        if (
                            "started on port" in content
                            or "running on http" in content
                        ):
                            match = re.search(
                                r"port\s+(\d+)", content
                            ) or re.search(r"127\.0\.0\.1:(\d+)", content)
                            if match:
                                allocated_port = int(match.group(1))
                                break
                    except (OSError, UnicodeDecodeError):
                        pass

            boot_log.close()

            if allocated_port:
                # Perform TCP socket ping to verify port is open
                port_ready = False
                for _ in range(100):  # 10s max timeout
                    try:
                        with socket.create_connection(
                            ("127.0.0.1", allocated_port), timeout=0.5
                        ):
                            port_ready = True
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)

                if port_ready:
                    self.active_server_port = allocated_port
                    self.console.print(
                        "[bold green]✓ Server loaded successfully on port "
                        f"{allocated_port}![/]"
                    )
                    return allocated_port

            # Attempt failed: Clean up process handle before retrying
            try:
                server_proc.terminate()
                server_proc.wait(timeout=2)
            except (OSError, subprocess.SubprocessError):
                try:
                    server_proc.kill()
                except (OSError, subprocess.SubprocessError):
                    pass
            self.active_server_process = None

            self.console.print(
                "[bold red]⚠ Uvicorn terminated prematurely or failed to "
                "bind. Retrying in 2 seconds...[/]"
            )
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r", encoding="utf-8") as lf:
                        boot_logs = lf.read()
                    self.console.print(
                        "[dim]----- Uvicorn Boot Logs "
                        f"(Attempt {attempt+1}) -----\n{boot_logs}"
                        "--------------------------------------------[/]"
                    )
                except (OSError, UnicodeDecodeError) as le:
                    self.console.print(f"[dim]Failed to read boot log: {le}[/]")
            time.sleep(2.0)

        raise RuntimeError(
            "Fatal: Failed to start background ADK server after 3 attempts."
        )

    def stop_adk_server(self, env_map=None):
        del env_map
        if self.active_server_process:
            try:
                self.active_server_process.terminate()
                self.active_server_process.wait(timeout=3)
            except (OSError, subprocess.SubprocessError):
                try:
                    self.active_server_process.kill()
                except (OSError, subprocess.SubprocessError):
                    pass
        self.force_kill_port(self.active_server_port)
        time.sleep(2.0)
