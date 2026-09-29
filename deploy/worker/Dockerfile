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
# The wheel's Playwright and the image's bundled Chromium must be the same
# version, or the browser cannot launch ("Executable doesn't exist …"). Keep
# this ARG and the FROM tag in lockstep; the pip step pins the wheel to it.
ARG PLAYWRIGHT_VERSION=1.55.0
FROM mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-noble
ARG PLAYWRIGHT_VERSION

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    NODE_MAJOR=20 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Node is only needed for the optional Claude Code executor. git is needed to
# check out an operator-approved grey-box source repository for a run.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates git \
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
# The wheel build force-includes these contract directories (see pyproject
# [tool.hatch.build.targets.wheel]); without them the metadata step fails.
COPY schemas ./schemas
COPY catalog ./catalog
COPY rules ./rules
# Pin the wheel's Playwright to the base image's version so it never drifts
# ahead of the image's bundled browser, then make sure Chromium is present for
# it under PLAYWRIGHT_BROWSERS_PATH.
RUN python -m pip install ".[web]" "playwright==${PLAYWRIGHT_VERSION}" \
 && python -m playwright install chromium

COPY deploy/worker/entrypoint.sh /usr/local/bin/sechelix-worker-entrypoint
RUN chmod +x /usr/local/bin/sechelix-worker-entrypoint \
 && useradd --create-home --uid 10001 worker \
 && mkdir -p /data && chown worker:worker /data
USER worker
ENV WORKER_ROOT=/data
# Chromium runs as this non-root user inside the container, where its own
# sandbox helper is unavailable; the container is the isolation boundary.
ENV SECHELIX_BROWSER_NO_SANDBOX=1

ENTRYPOINT ["/usr/local/bin/sechelix-worker-entrypoint"]
