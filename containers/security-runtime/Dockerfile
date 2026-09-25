FROM python:3.12.11-slim-bookworm

ARG SEMGREP_VERSION=1.140.0
ARG GITLEAKS_VERSION=8.28.0
ARG TRIVY_VERSION=0.66.0
ARG PIP_AUDIT_VERSION=2.9.0

RUN useradd --create-home --uid 10001 sechelix \
 && python -m pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" "pip-audit==${PIP_AUDIT_VERSION}" \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl tar \
 && arch="$(dpkg --print-architecture)" \
 && case "$arch" in amd64) goarch=x86_64;; arm64) goarch=arm64;; *) exit 1;; esac \
 && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${goarch}.tar.gz" -o /tmp/gitleaks.tgz \
 && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
 && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${goarch}.tar.gz" -o /tmp/trivy.tgz \
 && tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy \
 && rm -rf /var/lib/apt/lists/* /tmp/*.tgz

USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/bin/env"]
