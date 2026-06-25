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

"""CLI model selection utilities."""

import os
import sys

import google.auth
from app.cli.bootstrap import get_fallback_models
from google import genai
from google.genai import types
from rich.console import Console


def select_gcp_vertex_models(
    pro_override=None,
    flash_override=None,
    location_override=None,
    gemma_endpoint=None,
):
    console = Console()
    if gemma_endpoint:
        pro_model = pro_override or "google/gemma-4-E4B-it"
        flash_model = flash_override or "google/gemma-4-E2B-it"
        console.print(
            "\n[bold green]✓ Configured Gemma 4 scan engines on Cloud Run "
            "vLLM endpoint:[/]\n  PRO: [underline cyan]"
            f"{pro_model}[/] | FLASH: [underline cyan]{flash_model}[/] | "
            f"Endpoint: [underline cyan]{gemma_endpoint}[/]\n"
        )
        return pro_model, flash_model

    if not pro_override or not flash_override:
        console.print(
            "[bold yellow]↻ Querying Vertex AI for available Gemini models "
            "inside subscription...[/]"
        )

    project_id = "N/A (Google AI Studio)"
    client = None
    probe_client = None

    def init_genai_clients():
        nonlocal client, probe_client, project_id
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key:
            old_adc = os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
            try:
                client = genai.Client(
                    api_key=api_key,
                    vertexai=False,
                    http_options={"timeout": 600.0},
                )
                probe_client = genai.Client(api_key=api_key, vertexai=False)
                project_id = "N/A (Google AI Studio)"
            finally:
                if old_adc:
                    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = old_adc
        else:
            credentials, auth_project = google.auth.default()
            project_id = (
                os.environ.get("GOOGLE_CLOUD_PROJECT")
                or os.environ.get("VULNCATCHER_PROJECT")
                or auth_project
            )
            try:
                if hasattr(credentials, "with_quota_project"):
                    credentials = credentials.with_quota_project(project_id)
            except (AttributeError, TypeError, ValueError):
                pass

            location = location_override or os.environ.get(
                "GOOGLE_CLOUD_LOCATION", "global"
            )
            client = genai.Client(
                credentials=credentials,
                project=project_id,
                location=location,
                vertexai=True,
                http_options={"timeout": 600.0},
            )
            probe_client = genai.Client(
                credentials=credentials,
                project=project_id,
                location=location,
                vertexai=True,
            )

    try:
        init_genai_clients()

        def verify_model_generation_access(model_name):
            if not model_name.startswith("gemini-"):
                return True
            nonlocal client, probe_client, project_id
            try:
                probe_client.models.generate_content(
                    model=model_name,
                    contents="ping",
                    config=types.GenerateContentConfig(
                        max_output_tokens=1, temperature=0.0
                    ),
                )
                return True
            except (AttributeError, RuntimeError, ValueError) as e:
                if "temperature" in str(e).lower():
                    try:
                        probe_client.models.generate_content(
                            model=model_name,
                            contents="ping",
                            config=types.GenerateContentConfig(
                                max_output_tokens=1
                            ),
                        )
                        return True
                    except (
                        AttributeError,
                        RuntimeError,
                        ValueError,
                        TypeError,
                        KeyError,
                    ) as r_err:
                        e = r_err

                # Clean up error message by stripping out raw JSON dumps
                err_msg = str(e)
                if "{" in err_msg:
                    raw = err_msg.split("{", maxsplit=1)[0]
                    err_msg = raw.strip().rstrip(".")

                if os.environ.get("GEMINI_API_KEY"):
                    console.print(
                        "\n[bold yellow]⚠️ GEMINI_API_KEY pre-flight "
                        f"check failed: {err_msg}[/]"
                    )
                    console.print(
                        "[bold yellow]Automatically falling back to "
                        "Google Cloud Vertex AI (ADC)...[/]\n"
                    )
                    os.environ.pop("GEMINI_API_KEY", None)
                    init_genai_clients()
                    try:
                        probe_client.models.generate_content(
                            model=model_name,
                            contents="ping",
                            config=types.GenerateContentConfig(
                                max_output_tokens=1, temperature=0.0
                            ),
                        )
                        return True
                    except (
                        AttributeError,
                        KeyError,
                        OSError,
                        RuntimeError,
                        TypeError,
                        ValueError,
                    ) as retry_err:
                        # Catching specific errors because probe errors vary
                        if "temperature" in str(retry_err).lower():
                            try:
                                probe_client.models.generate_content(
                                    model=model_name,
                                    contents="ping",
                                    config=types.GenerateContentConfig(
                                        max_output_tokens=1
                                    ),
                                )
                                return True
                            except (
                                AttributeError,
                                KeyError,
                                OSError,
                                RuntimeError,
                                TypeError,
                                ValueError,
                            ) as second_retry_err:
                                err_msg = str(second_retry_err)
                        else:
                            err_msg = str(retry_err)

                console.print(
                    "\n[bold red]✗ Pre-flight Access Check Failed for "
                    f"{model_name}:[/]"
                )
                if "404" in err_msg or "NOT_FOUND" in err_msg:
                    console.print(
                        "  [yellow]API Error:[/] Model was not found or your "
                        f"active GCP Project [underline cyan]{project_id}[/] "
                        "does not have access allowlisted."
                    )
                else:
                    console.print(f"  [yellow]API Error:[/] {err_msg}")
                return False

        if pro_override and flash_override:
            console.print(
                "[bold yellow]↻ CLI overrides detected. Verifying "
                "subscription access dynamically...[/]"
            )
            console.print(
                "[dim]  ⌛ Verifying model subscription access on "
                f"{pro_override}...[/]"
            )
            if not verify_model_generation_access(pro_override):
                console.print(
                    f"[bold red]✗ CLI Override PRO model '{pro_override}' "
                    f"not allowlisted in project '{project_id}'.[/]"
                )
                sys.exit(1)
            console.print(
                "[dim]  ⌛ Verifying model subscription access on "
                f"{flash_override}...[/]"
            )
            if not verify_model_generation_access(flash_override):
                console.print(
                    f"[bold red]✗ CLI Override FLASH model '{flash_override}' "
                    f"not allowlisted in project '{project_id}'.[/]"
                )
                sys.exit(1)
            console.print(
                "\n[bold green]✓ Configured scan engines dynamically "
                f"(CLI Overrides):[/] PRO: {pro_override} | "
                f"FLASH: {flash_override}\n"
            )
            return pro_override, flash_override

        gemini_models = []
        for m in client.models.list():
            name = m.name.split("/")[-1]
            if (
                name.startswith("gemini-")
                and not name.endswith("-image")
                and not name.endswith("-tts")
            ):
                gemini_models.append(name)

        if not gemini_models:
            raise RuntimeError(
                "No active Gemini models found in your Vertex subscription."
            )

        gemini_models = sorted(list(set(gemini_models)))

        while True:
            console.print(
                "\n[bold cyan]🤖 Select your Reasoning & Remediation Engine:[/]"
            )
            console.print(
                "[dim]   ↳ Used for Triage Critic Filtering, reachability "
                "tracing, AST mocking, and Git diff patch synthesis.[/]"
            )
            for idx, m in enumerate(gemini_models):
                console.print(f"  [bold green]{idx + 1}[/] • {m}")

            pro_sel = console.input(
                f"\n[bold green]? Enter choice (1-{len(gemini_models)}, "
                "default: 1): [/]"
            ).strip()
            pro_idx = 0
            if pro_sel.isdigit():
                val = int(pro_sel) - 1
                if 0 <= val < len(gemini_models):
                    pro_idx = val
            pro_model = gemini_models[pro_idx]

            console.print(
                "[dim]  ⌛ Verifying model subscription access on "
                f"{pro_model}...[/]"
            )
            if verify_model_generation_access(pro_model):
                break

        while True:
            console.print(
                "\n[bold cyan]⚡ Select your Vulnerability Discovery Engine:[/]"
            )
            console.print(
                "[dim]   ↳ Used for initial codebase playbooks walks, "
                "directories walks, and files scanning.[/]"
            )
            for idx, m in enumerate(gemini_models):
                console.print(f"  [bold green]{idx + 1}[/] • {m}")

            flash_sel = console.input(
                f"\n[bold green]? Enter choice (1-{len(gemini_models)}, "
                "default: 1): [/]"
            ).strip()
            flash_idx = 0
            if flash_sel.isdigit():
                val = int(flash_sel) - 1
                if 0 <= val < len(gemini_models):
                    flash_idx = val
            flash_model = gemini_models[flash_idx]

            console.print(
                "[dim]  ⌛ Verifying model subscription access on "
                f"{flash_model}...[/]"
            )
            if verify_model_generation_access(flash_model):
                break

        console.print(
            "\n[bold green]✓ Configured scan engines dynamically:[/] "
            f"REASONING: {pro_model} | DISCOVERY: {flash_model}\n"
        )
        return pro_model, flash_model

    except Exception as e:  # pylint: disable=broad-exception-caught
        # Catching Exception because model discovery errors vary
        fb_pro, fb_flash = get_fallback_models()
        console.print(
            f"[bold yellow]⚠️ Dynamic models discovery bypassed: {str(e)}[/]"
        )
        console.print(
            "[bold yellow]Checking availability of fallback engine: "
            f"{fb_flash}...[/]"
        )
        if not verify_model_generation_access(fb_flash):
            console.print(
                f"[bold red]✗ Fallback model '{fb_flash}' is also not "
                "available/authorized.[/]"
            )
            console.print(
                "[bold red]Stopping execution because the model is not "
                "available.[/]"
            )
            sys.exit(1)
        console.print(
            "[bold green]✓ Using standard fallback engines: "
            f"{fb_pro} & {fb_flash}[/]\n"
        )
        return fb_pro, fb_flash
