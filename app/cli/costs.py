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

"""Cost calculation utilities."""

import json
import os
import sqlite3
from pathlib import Path

import requests
from app.cli.bootstrap import get_fallback_models


def calculate_session_token_costs(session_ids):
    db_path = str(Path(__file__).parent.parent / ".adk" / "session.db")
    if not os.path.exists(db_path):
        return None

    if isinstance(session_ids, str):
        session_ids = [session_ids]

    fb_pro, fb_flash = get_fallback_models()
    pro_model_name = os.environ.get("VULNCATCHER_PRO_MODEL", fb_pro)
    flash_model_name = os.environ.get("VULNCATCHER_FLASH_MODEL", fb_flash)

    pro_in_rate = 0.0
    pro_out_rate = 0.0
    flash_in_rate = 0.0
    flash_out_rate = 0.0
    pricing_source = "Local Baseline Config"

    pricing_url = (
        "https://raw.githubusercontent.com/BerriAI/litellm/main/"
        "model_prices_and_context_window.json"
    )
    local_prices_path = str(
        Path(__file__).parent.parent / "app_utils" / "default_prices.json"
    )
    try:
        if os.path.exists(local_prices_path):
            with open(local_prices_path, encoding="utf-8") as f:
                data = json.load(f)

                fallback_pro = fb_pro
                fallback_flash = fb_flash

                pro_key = (
                    pro_model_name
                    if pro_model_name in data["models"]
                    else fallback_pro
                )
                flash_key = (
                    flash_model_name
                    if flash_model_name in data["models"]
                    else fallback_flash
                )

                pro_in_rate = data["models"][pro_key]["input_cost_per_token"]
                pro_out_rate = data["models"][pro_key]["output_cost_per_token"]
                flash_in_rate = data["models"][flash_key][
                    "input_cost_per_token"
                ]
                flash_out_rate = data["models"][flash_key][
                    "output_cost_per_token"
                ]
                pricing_url = data.get("pricing_url", pricing_url)
    except (json.JSONDecodeError, KeyError, OSError, TypeError):
        pass

    try:
        pricing_resp = requests.get(pricing_url, timeout=2.0)
        if pricing_resp.ok:
            prices = pricing_resp.json()
            pro_info = prices.get(pro_model_name) or prices.get(
                f"vertex_ai/{pro_model_name}"
            )
            if pro_info:
                pro_in_rate = pro_info.get("input_cost_per_token", pro_in_rate)
                pro_out_rate = pro_info.get(
                    "output_cost_per_token", pro_out_rate
                )
            flash_info = prices.get(flash_model_name) or prices.get(
                f"vertex_ai/{flash_model_name}"
            )
            if flash_info:
                flash_in_rate = flash_info.get(
                    "input_cost_per_token", flash_in_rate
                )
                flash_out_rate = flash_info.get(
                    "output_cost_per_token", flash_out_rate
                )
            pricing_source = "LiteLLM Live Catalog"
    except (requests.RequestException, ValueError):
        pass

    pro_in = 0
    pro_out = 0
    flash_in = 0
    flash_out = 0

    try:
        conn = sqlite3.connect(db_path)
        placeholders = ",".join("?" for _ in session_ids)
        query = (
            "SELECT event_data FROM events WHERE "
            f"session_id IN ({placeholders})"
        )
        rows = conn.execute(query, tuple(session_ids)).fetchall()
        conn.close()

        for row in rows:
            try:
                evt = json.loads(row[0])
                usage = evt.get("usage_metadata")
                if usage:
                    model = evt.get("model_version", "")
                    in_tokens = usage.get("prompt_token_count") or usage.get(
                        "prompt_tokens", 0
                    )
                    out_tokens = usage.get(
                        "candidates_token_count"
                    ) or usage.get("completion_tokens", 0)

                    if "flash" in model.lower():
                        flash_in += in_tokens
                        flash_out += out_tokens
                    else:
                        pro_in += in_tokens
                        pro_out += out_tokens
            except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
                pass
    except sqlite3.Error:
        return None

    pro_cost = (pro_in * pro_in_rate) + (pro_out * pro_out_rate)
    flash_cost = (flash_in * flash_in_rate) + (flash_out * flash_out_rate)
    total_cost = pro_cost + flash_cost

    discount_env = os.environ.get("VULNCATCHER_ENTERPRISE_DISCOUNT")
    discount_label = ""
    if discount_env:
        try:
            discount_val = float(discount_env)
            if 0.0 < discount_val < 1.0:
                total_cost = total_cost * (1.0 - discount_val)
                discount_label = (
                    " (Custom Enterprise Discount of "
                    f"{int(discount_val * 100)}% applied)"
                )
        except ValueError:
            pass

    return {
        "pro_in": pro_in,
        "pro_out": pro_out,
        "flash_in": flash_in,
        "flash_out": flash_out,
        "total_cost": total_cost,
        "pricing_source": pricing_source,
        "discount_label": discount_label,
    }
