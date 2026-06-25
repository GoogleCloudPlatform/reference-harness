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

FROM python:3.12-slim

# Install system dependencies and SAST scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl && \
    rm -rf /var/lib/apt/lists/*

# Install uv and google-agents-cli
RUN pip install --no-cache-dir uv==0.8.13 && \
    uv tool install "google-agents-cli>=0.2.0"
ENV PATH="/root/.local/bin:${PATH}"

# Install Semgrep
RUN pip install --no-cache-dir semgrep==1.168.0

# Install Gitleaks
ARG GITLEAKS_VERSION=8.30.1
ENV GITLEAKS_VERSION=${GITLEAKS_VERSION}
RUN curl -sSLo /tmp/gitleaks.tar.gz \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz

# Install Trivy
# hadolint ignore=DL3059,DL4006
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Bandit
# hadolint ignore=DL3059
RUN pip install --no-cache-dir bandit==1.9.4

WORKDIR /code

COPY ./pyproject.toml ./README.md ./uv.lock* ./
COPY ./app ./app
COPY ./scan.py ./scan.py
COPY ./entrypoint.sh ./entrypoint.sh

ENV UV_DEFAULT_INDEX=https://pypi.org/simple
ENV UV_INDEX_URL=https://pypi.org/simple

RUN agents-cli install && \
    uv sync --frozen --extra eval

ARG COMMIT_SHA=""
ENV COMMIT_SHA=${COMMIT_SHA}

ARG AGENT_VERSION=0.0.0
ENV AGENT_VERSION=${AGENT_VERSION}

EXPOSE 8080

# Health check for Cloud Run
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:8080/healthz || exit 1

CMD ["uv", "run", "uvicorn", "app.fast_api_app:app", "--host", "0.0.0.0", "--port", "8080"]
