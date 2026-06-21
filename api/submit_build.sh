#!/bin/bash
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

set -euox pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <image_tag>"
  exit 1
fi

IMAGE_TAG="$1"

# Determine repository root relative to this script
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_TMP="$REPO_ROOT/build_tmp"

echo "🧹 Cleaning up any old temporary build directories..."
rm -rf "$BUILD_TMP"

echo "📦 Staging required source code files into $BUILD_TMP..."
mkdir -p "$BUILD_TMP"
cp "$REPO_ROOT/Dockerfile" "$REPO_ROOT/pyproject.toml" "$REPO_ROOT/README.md" "$REPO_ROOT/entrypoint.sh" "$REPO_ROOT/uv.lock" "$REPO_ROOT/scan.py" "$BUILD_TMP/"
#cp "$REPO_ROOT/Dockerfile" "$REPO_ROOT/pyproject.toml" "$REPO_ROOT/README.md" "$REPO_ROOT/entrypoint.sh" "$REPO_ROOT/scan.py" "$BUILD_TMP/"
cp -r "$REPO_ROOT/app" "$BUILD_TMP/"

echo "🚀 Submitting container build to Google Cloud Build..."
gcloud builds submit --tag "$IMAGE_TAG" "$BUILD_TMP"

echo "🧹 Cleaning up temporary build directory..."
# rm -rf "$BUILD_TMP"

echo "✓ Container image built and pushed successfully to: $IMAGE_TAG"
