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

set -euo pipefail

echo "===================================================="
echo "🚀 Building Reference Harness Standalone Binary..."
echo "===================================================="

# Verify uv is installed
if ! command -v uv &>/dev/null; then
  echo "❌ Error: 'uv' package manager not found. Please install 'uv' to proceed."
  exit 1
fi

# Clean previous builds if they exist
echo "🧹 Cleaning previous builds..."
rm -rf build/ dist/

# Execute PyInstaller build using uv
echo "📦 Compiling standalone binary with PyInstaller..."
uv run pyinstaller rh.spec

echo "===================================================="
echo "✓ Build complete! Standalone binary generated at:"
echo "  dist/rh"
echo "===================================================="

# Test run help
echo "🧪 Performing self-test execution..."
./dist/rh --help >/dev/null

echo "✓ Binary self-test succeeded! Ready for production deployment."
echo "===================================================="
