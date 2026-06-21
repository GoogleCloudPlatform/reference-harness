import os
import sys

from app.cli.bootstrap import get_fallback_models
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
            f"\n[bold green]✓ Configured Gemma 4 scan engines on Cloud Run vLLM endpoint:[/]\n  PRO: [underline cyan]{pro_model}[/] | FLASH: [underline cyan]{flash_model}[/] | Endpoint: [underline cyan]{gemma_endpoint}[/]\n"
        )
        return pro_model, flash_model

    if not pro_override or not flash_override:
        console.print(
            "[bold yellow]↻ Querying Vertex AI for available Gemini models inside your subscription...[/]"
        )

    import google.auth
    from google import genai

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
            except Exception:
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
        from google.genai import types

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
            except Exception as e:
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
                    except Exception as retry_err:
                        e = retry_err

                # Clean up the error message by stripping out raw JSON dumps
                err_msg = str(e)
                if "{" in err_msg:
                    err_msg = err_msg.split("{")[0].strip().rstrip(".")

                if os.environ.get("GEMINI_API_KEY"):
                    console.print(
                        f"\n[bold yellow]⚠️ GEMINI_API_KEY pre-flight check failed: {err_msg}[/]"
                    )
                    console.print(
                        "[bold yellow]Automatically falling back to Google Cloud Vertex AI (ADC)...[/]\n"
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
                    except Exception as retry_err:
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
                            except Exception as second_retry_err:
                                err_msg = str(second_retry_err)
                        else:
                            err_msg = str(retry_err)

                console.print(
                    f"\n[bold red]✗ Pre-flight Access Check Failed for {model_name}:[/]"
                )
                if "404" in err_msg or "NOT_FOUND" in err_msg:
                    console.print(
                        f"  [yellow]API Error:[/] Model was not found or your active GCP Project [underline cyan]{project_id}[/] does not have billing/quota access allowlisted for it."
                    )
                else:
                    console.print(f"  [yellow]API Error:[/] {err_msg}")
                return False

        if pro_override and flash_override:
            console.print(
                f"[bold yellow]↻ CLI overrides detected. Verifying subscription access dynamically...[/]"
            )
            console.print(
                f"[dim]  ⌛ Verifying model subscription access on {pro_override}...[/]"
            )
            if not verify_model_generation_access(pro_override):
                console.print(
                    f"[bold red]✗ CLI Override PRO model '{pro_override}' is not supported/allowlisted inside project '{project_id}'.[/]"
                )
                sys.exit(1)
            console.print(
                f"[dim]  ⌛ Verifying model subscription access on {flash_override}...[/]"
            )
            if not verify_model_generation_access(flash_override):
                console.print(
                    f"[bold red]✗ CLI Override FLASH model '{flash_override}' is not supported/allowlisted inside project '{project_id}'.[/]"
                )
                sys.exit(1)
            console.print(
                f"\n[bold green]✓ Configured scan engines dynamically (CLI Overrides):[/] PRO: [underline cyan]{pro_override}[/] | FLASH: [underline cyan]{flash_override}[/]\n"
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
            raise Exception(
                "No active Gemini models found in your Vertex subscription."
            )

        gemini_models = sorted(list(set(gemini_models)))

        while True:
            console.print(
                "\n[bold cyan]🤖 Select your Reasoning & Remediation Engine:[/]"
            )
            console.print(
                "[dim]   ↳ Used for Triage Critic Filtering, reachability tracing, AST mocking, and Git diff patch synthesis.[/]"
            )
            for idx, m in enumerate(gemini_models):
                console.print(f"  [bold green]{idx + 1}[/] • {m}")

            pro_sel = console.input(
                f"\n[bold green]? Enter choice (1-{len(gemini_models)}, default: 1): [/]"
            ).strip()
            pro_idx = 0
            if pro_sel.isdigit():
                val = int(pro_sel) - 1
                if 0 <= val < len(gemini_models):
                    pro_idx = val
            pro_model = gemini_models[pro_idx]

            console.print(
                f"[dim]  ⌛ Verifying model subscription access on {pro_model}...[/]"
            )
            if verify_model_generation_access(pro_model):
                break

        while True:
            console.print(
                "\n[bold cyan]⚡ Select your Vulnerability Discovery Engine:[/]"
            )
            console.print(
                "[dim]   ↳ Used for initial codebase playbooks walks, directories walks, and files scanning.[/]"
            )
            for idx, m in enumerate(gemini_models):
                console.print(f"  [bold green]{idx + 1}[/] • {m}")

            flash_sel = console.input(
                f"\n[bold green]? Enter choice (1-{len(gemini_models)}, default: 1): [/]"
            ).strip()
            flash_idx = 0
            if flash_sel.isdigit():
                val = int(flash_sel) - 1
                if 0 <= val < len(gemini_models):
                    flash_idx = val
            flash_model = gemini_models[flash_idx]

            console.print(
                f"[dim]  ⌛ Verifying model subscription access on {flash_model}...[/]"
            )
            if verify_model_generation_access(flash_model):
                break

        console.print(
            f"\n[bold green]✓ Configured scan engines dynamically:[/] REASONING: [underline cyan]{pro_model}[/] | DISCOVERY: [underline cyan]{flash_model}[/]\n"
        )
        return pro_model, flash_model

    except Exception as e:
        fb_pro, fb_flash = get_fallback_models()
        console.print(
            f"[bold yellow]⚠️ Dynamic models discovery bypassed: {str(e)}[/]"
        )
        console.print(
            f"[bold yellow]Checking availability of fallback engine: {fb_flash}...[/]"
        )
        if not verify_model_generation_access(fb_flash):
            console.print(
                f"[bold red]✗ Fallback model '{fb_flash}' is also not available/authorized.[/]"
            )
            console.print(
                "[bold red]Stopping execution because the model is not available.[/]"
            )
            sys.exit(1)
        console.print(
            f"[bold green]✓ Using standard fallback engines: {fb_pro} & {fb_flash}[/]\n"
        )
        return fb_pro, fb_flash
