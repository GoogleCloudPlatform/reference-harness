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
"""Thin CLI wrapper for VulnCatcher."""

import multiprocessing
import os
import sys

from app.cli.main import entry_point

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if os.environ.get("VULNCATCHER_ADK_SERVER_MODE") == "1":
        del os.environ["VULNCATCHER_ADK_SERVER_MODE"]
        from google.adk.cli import main as adk_main

        sys.exit(adk_main())
    else:
        entry_point()
