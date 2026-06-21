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
set -euox pipefail

PRO_MODEL=""
FLASH_MODEL=""
GIT_REPO=""
GIT_REF=""
LOG_FILE=""

echo "Execution ID: $${CLOUD_RUN_EXECUTION}"

parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --pro-model)
                shift
                PRO_MODEL="$1"
                ;;
            --flash-model)
                shift
                FLASH_MODEL="$1"
                ;;
            --repo)
                shift
                GIT_REPO="$1"
                ;;
            --ref)
                shift
                GIT_REF="$1"
                ;;
            *) echo "Unknown parameter passed: $1"; exit 1;;
        esac
        shift
    done

    echo "Pro Model: $${PRO_MODEL}"
    echo "Flash Model: $${FLASH_MODEL}"
    echo "Git Repo: $${GIT_REPO}"
    echo "Git Ref: $${GIT_REF}"
}

parse_args "$@"

# Clone the repository
echo "🚀 Cloning repository: $${GIT_REPO}"

# Create a temporary directory
TMP_DIR=$(mktemp -d)

# Clone the repository into the temporary directory
git clone "$${GIT_REPO}" "$${TMP_DIR}"
pushd "$${TMP_DIR}"
git checkout "$${GIT_REF}"
popd

# Create a ./reports directory
mkdir ./reports

# Run scan.py in the background and capture its PID
echo "Running scan.py with $${PRO_MODEL} and $${FLASH_MODEL}"
UV_DEFAULT_INDEX=https://pypi.org/simple UV_INDEX_URL=https://pypi.org/simple uv run scan.py "$${TMP_DIR}" --pro-model "$${PRO_MODEL}" --flash-model "$${FLASH_MODEL}" 2>&1 | tee ./reports/scan.log &
SCAN_PID=$!

# Periodically sync reports bucket in the background while scan.py runs
(
    while kill -0 $SCAN_PID 2>/dev/null; do
        sleep 300 # sync every 5 minutes
        echo "Syncing reports to GCS..."
        gcloud storage cp -r ./reports "gs://${REPORT_BUCKET}/$${CLOUD_RUN_EXECUTION}/" || true
    done
) &
SYNC_PID=$!

# Wait for scan.py to complete
wait $SCAN_PID
SCAN_EXIT_CODE=$?

# Terminate the background sync loop and perform one final sync
kill $SYNC_PID 2>/dev/null || true

# Upload reports to GCS
echo "Uploading reports to GCS"
gcloud storage cp -r ./reports "gs://${REPORT_BUCKET}/$${CLOUD_RUN_EXECUTION}/"
