#!/usr/bin/env bash
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

#shellcheck disable=all

echo "Obtaining identity token"
export ID_TOKEN=$(gcloud auth print-identity-token)

echo "Calling API. This may take a few moments..."
RESPONSE=$(curl -s -X POST "${API_URL}/run" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "proModel": "gemini-3.5-flash",
    "flashModel": "gemini-3.5-flash",
    "repo": "https://github.com/c6fc/styx_azuread.git",
    "ref": "main"
  }')

echo "Response received:"
echo "$RESPONSE" | jq

EXECUTION_ID=$(echo "$RESPONSE" | jq -r '.executionId')

echo "Starting log view. ctrl-c to exit"

# Save cursor position so we can overwrite only the status output below
printf "\033[s"

while true; do
    # Restore cursor position and clear from cursor to end of screen
    printf "\033[u\033[J"
    curl -s "${API_URL}/status/$${EXECUTION_ID}" \
        -H "Authorization: Bearer $ID_TOKEN" | jq
    sleep 60
done
