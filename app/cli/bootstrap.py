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

"""Codebase bootstrapping utilities."""

import glob
import json
import os
import sys
from pathlib import Path

import google.auth
import requests
from google import genai
from google.genai import types
from rich.console import Console

try:
    import litellm

    litellm.suppress_debug_info = True
except (ImportError, AttributeError):
    pass


def get_fallback_models():
    local_prices_path = str(
        Path(__file__).parent.parent / "app_utils" / "default_prices.json"
    )
    fallback_pro = None
    fallback_flash = None

    if not os.path.exists(local_prices_path):
        raise FileNotFoundError(
            f"Critical configuration file '{local_prices_path}' is missing! "
            "Please restore this file to run Reference Harness scans."
        )

    try:
        with open(local_prices_path, encoding="utf-8") as f:
            data = json.load(f)
            if "default_models" in data:
                fallback_pro = data["default_models"].get("pro")
                fallback_flash = data["default_models"].get("flash")
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as err:
        raise ValueError(
            f"Failed to parse default_prices.json registry: {str(err)}"
        ) from err

    if not fallback_pro or not fallback_flash:
        raise ValueError(
            "Centralized default_prices.json registry is missing required "
            "'default_models' definitions!"
        )

    return fallback_pro, fallback_flash


def bootstrap_codebase_signatures(target_dir, flash_model=None):
    if not flash_model:
        _, flash_model = get_fallback_models()
    console = Console()
    console.print(
        "[bold yellow]↻ AI Bootstrapper scanning codebase configurations...[/]"
    )

    config_patterns = [
        "package.json",
        "Cargo.toml",
        "go.mod",
        "CMakeLists.txt",
        "requirements.txt",
        "Gemfile",
        "pnpm-workspace.yaml",
        "terraform.jsonnet",
        "cdk.json",
        "serverless.yml",
        "serverless.yaml",
        "template.yaml",
        "mix.exs",
    ]
    config_contents = {}

    for pattern in config_patterns:
        matches = glob.glob(
            os.path.join(target_dir, "**", pattern), recursive=True
        )
        for path in matches[:3]:
            try:
                if any(
                    x in path
                    for x in ["node_modules", ".venv", "dist", "build"]
                ):
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(3000)
                config_contents[os.path.relpath(path, target_dir)] = content
            except (OSError, UnicodeError):
                pass

    configs_desc = ""
    if not config_contents:
        unique_extensions = set()
        try:
            for _, dirs, files in os.walk(target_dir):
                dirs[:] = [
                    d
                    for d in dirs
                    if d
                    not in [
                        ".git",
                        "node_modules",
                        ".venv",
                        "venv",
                        "dist",
                        "build",
                        ".adk",
                    ]
                ]
                for file in files[:100]:
                    _, ext = os.path.splitext(file.lower())
                    if ext and ext not in [
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
                        ".md",
                        ".txt",
                    ]:
                        unique_extensions.add(ext)
        except OSError:
            pass

        if unique_extensions:
            ext_list = ", ".join(sorted(unique_extensions))
            configs_desc = (
                "=== Codebase Extensions (No manifests found) ===\n"
                f"Codebase contains these file extensions: {ext_list}\n\n"
            )
        else:
            return None
    else:
        for name, content in config_contents.items():
            configs_desc += f"=== File: {name} ===\n{content}\n\n"

    try:
        gemma_endpoint = os.environ.get("VULNCATCHER_GEMMA_ENDPOINT")
        prompt = f"""You are the Bootstrap Discovery phase of a codebase audit.
Based on these root project configuration files, analyze the programming languages, frameworks, libraries, and infrastructure setups used:

{configs_desc}

1. Analyze the codebase to identify all applicable codebase stack profiles present.
   - You may use standard profiles ("web", "systems", "iac") OR **dynamically define and create your own custom category keys** (e.g. "mobile", "smart_contracts", "embedded", "desktop") if they better map the technology stack.

2. For each applicable category (standard or custom), compile a list of case-sensitive regular expression patterns (patterns), directory/filename keywords (filenames), and/or code file extensions (extensions) used to target attack surfaces, routes, interfaces, or configs.
   - IMPORTANT: In low-level system profiles, to prevent matching standard language calls like .bind(this), ALWAYS enforce word boundaries (\\b) and negative lookbehinds (?<!\\.) on common system calls (e.g. "(?<!\\.)\\bbind\\(").

Return strictly a single JSON object with no prose, no markdown fences, containing a dictionary of all detected categories alongside a dynamic "primary_category" naming the majority stack:
{{
  "primary_category": "name_of_the_primary_stack",
  "name_of_category_1": {{
    "patterns": ["regex_pattern_1", ...],
    "filenames": ["filename_keyword_1", ...],
    "extensions": [".ext_1", ...]
  }},
  "name_of_category_2": {{
    "patterns": ["regex_pattern_2", ...],
    "filenames": ["filename_keyword_2", ...],
    "extensions": [".ext_2", ...]
  }}
}}
"""
        if gemma_endpoint:
            url = gemma_endpoint.rstrip("/") + "/v1/chat/completions"
            payload = {
                "model": flash_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "response_format": {"type": "json_object"},
            }
            headers = {"Content-Type": "application/json"}
            resp = requests.post(
                url, json=payload, headers=headers, timeout=60.0
            )
            if not resp.ok:
                raise RuntimeError(
                    "Gemma classification failed "
                    f"(HTTP {resp.status_code}): {resp.text}"
                )
            res_text = resp.json()["choices"][0]["message"]["content"]
            res_data = json.loads(res_text.strip())
        else:
            if not flash_model.startswith("gemini-"):
                litellm_model = flash_model
                if not litellm_model.startswith(
                    "vertex_ai/"
                ) and not litellm_model.startswith("openai/"):
                    litellm_model = f"vertex_ai/{litellm_model}"

                _, auth_project = google.auth.default()
                project_id = (
                    os.environ.get("GOOGLE_CLOUD_PROJECT")
                    or os.environ.get("VULNCATCHER_PROJECT")
                    or auth_project
                )
                location = os.environ.get("GOOGLE_CLOUD_LOCATION", "global")

                os.environ["VERTEX_PROJECT"] = project_id
                os.environ["VERTEX_LOCATION"] = location

                completion_kwargs = dict(
                    model=litellm_model,
                    messages=[{"role": "user", "content": prompt}],
                    vertex_project=project_id,
                    vertex_location=location,
                    temperature=0.0,
                )
                try:
                    response = litellm.completion(**completion_kwargs)
                except (
                    AttributeError,
                    KeyError,
                    OSError,
                    RuntimeError,
                    TypeError,
                    ValueError,
                ) as exc:
                    # Catching specific errors because LiteLLM errors vary
                    if (
                        "temperature" in str(exc).lower()
                        and "temperature" in completion_kwargs
                    ):
                        completion_kwargs.pop("temperature")
                        response = litellm.completion(**completion_kwargs)
                    else:
                        raise
                res_text = response.choices[0].message.content
                res_data = json.loads(res_text.strip())
            else:
                api_key = os.environ.get("GEMINI_API_KEY")
                if api_key:
                    old_adc = os.environ.pop(
                        "GOOGLE_APPLICATION_CREDENTIALS", None
                    )
                    try:
                        client = genai.Client(api_key=api_key, vertexai=False)
                    finally:
                        if old_adc:
                            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = (
                                old_adc
                            )
                else:
                    credentials, auth_project = google.auth.default()
                    project_id = (
                        os.environ.get("GOOGLE_CLOUD_PROJECT")
                        or os.environ.get("VULNCATCHER_PROJECT")
                        or auth_project
                    )
                    if hasattr(credentials, "with_quota_project"):
                        credentials = credentials.with_quota_project(project_id)

                    location = os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
                    client = genai.Client(
                        credentials=credentials,
                        project=project_id,
                        location=location,
                        vertexai=True,
                    )

                try:
                    response = client.models.generate_content(
                        model=flash_model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            temperature=0.0,
                        ),
                    )
                except (
                    AttributeError,
                    KeyError,
                    OSError,
                    RuntimeError,
                    TypeError,
                    ValueError,
                ) as exc:
                    # Catching specific errors because client API errors vary
                    if "temperature" in str(exc).lower():
                        response = client.models.generate_content(
                            model=flash_model,
                            contents=prompt,
                            config=types.GenerateContentConfig(
                                response_mime_type="application/json"
                            ),
                        )
                    else:
                        raise
                res_data = json.loads(response.text.strip())

        primary_cat = res_data.get("primary_category", "web")

        detected_cats = []
        for cat, cat_data in res_data.items():
            if cat == "primary_category" or not isinstance(cat_data, dict):
                continue
            if (
                cat_data.get("patterns")
                or cat_data.get("filenames")
                or cat_data.get("extensions")
            ):
                detected_cats.append(cat.upper())

        if len(detected_cats) > 1:
            cat_list = ", ".join(sorted(detected_cats))
            console.print(
                "✓ Codebase dynamically classified across multiple stacks: "
                f"[underline cyan]{cat_list}[/]!"
            )
        elif detected_cats:
            cat_0 = detected_cats[0]
            console.print(
                "✓ Codebase dynamically classified stack: "
                f"[underline cyan]{cat_0}[/]!"
            )
        else:
            primary_up = primary_cat.upper()
            console.print(
                "✓ Codebase primarily classified dynamically as "
                f"[underline cyan]{primary_up}[/]!"
            )

        sig_path = str(
            Path(__file__).parent.parent
            / "app_utils"
            / "framework_signatures.json"
        )
        if os.path.exists(sig_path):
            try:
                with open(sig_path, "r", encoding="utf-8") as sf:
                    sig_data = json.load(sf)

                for cat, cat_data in res_data.items():
                    if cat == "primary_category" or not isinstance(
                        cat_data, dict
                    ):
                        continue

                    sig_data.setdefault(cat, {})

                    if "patterns" in cat_data:
                        existing = set(sig_data[cat].get("patterns", []))
                        updated = sorted(
                            list(existing.union(cat_data["patterns"]))
                        )
                        sig_data[cat]["patterns"] = updated

                    if "filenames" in cat_data:
                        existing = set(sig_data[cat].get("filenames", []))
                        updated = sorted(
                            list(existing.union(cat_data["filenames"]))
                        )
                        sig_data[cat]["filenames"] = updated

                    if "extensions" in cat_data:
                        existing = set(sig_data[cat].get("extensions", []))
                        updated = sorted(
                            list(existing.union(cat_data["extensions"]))
                        )
                        sig_data[cat]["extensions"] = updated

                with open(sig_path, "w", encoding="utf-8") as sf:
                    json.dump(sig_data, sf, indent=2)
                console.print(
                    "✓ Autogenous signatures registry dynamically enriched "
                    "across all categories on disk!"
                )
            except (OSError, json.JSONDecodeError, TypeError) as se:
                console.print(
                    f"[bold yellow]⚠️ Signatures enrichment bypassed: {se}[/]"
                )

        boot_compatible_data = {
            "category": primary_cat,
            "patterns": res_data.get(primary_cat, {}).get("patterns", []),
            "filenames": res_data.get(primary_cat, {}).get("filenames", []),
        }
        return boot_compatible_data

    except Exception as e:  # pylint: disable=broad-exception-caught
        # Catching Exception because model classification errors vary
        console.print(f"[bold red]✗ AI Bootstrapper failed: {str(e)}[/]")
        console.print(
            "Stopping execution because the model is not available "
            "or failed to respond."
        )
        sys.exit(1)
