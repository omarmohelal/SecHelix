# SecHelix pentest worker for a hosted (Railway) deployment.
#
# This image is for testing targets you own or are explicitly authorized to
# test. The worker enforces the boundaries the base runtime already owns:
# deny-by-default scope, excluded hosts/paths, tighten-only per-run limits, and
# re-proven target ownership before every job. Nothing here relaxes them.
#
# The base is the official Playwright Python image, which ships Chromium and its
# system libraries at a version that matches the Playwright wheel, so browser
# launches are reproducible. The reasoning executor is optional: with
# ANTHROPIC_API_KEY set the entrypoint runs the claude-code executor, otherwise
# it runs executor "none" (browser discovery and bounded tools only, findings
# reported INCOMPLETE) so the service is healthy either way.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    NODE_MAJOR=20

# Node is only needed for the optional Claude Code executor.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && npm install -g @anthropic-ai/claude-code \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sechelix
COPY pyproject.toml ./
COPY docs/packaging/PYPI_README.md ./docs/packaging/PYPI_README.md
COPY sechelix_runner ./sechelix_runner
COPY sechelix_core ./sechelix_core
COPY adapters ./adapters
RUN python -m pip install ".[web]" \
 && python -m playwright install chromium

COPY deploy/worker/entrypoint.sh /usr/local/bin/sechelix-worker-entrypoint
RUN chmod +x /usr/local/bin/sechelix-worker-entrypoint \
 && useradd --create-home --uid 10001 worker \
 && mkdir -p /data && chown worker:worker /data
USER worker
ENV WORKER_ROOT=/data

ENTRYPOINT ["/usr/local/bin/sechelix-worker-entrypoint"]
