FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS builder

ENV SEMGREP_VERSION=1.140.0 \
    GITLEAKS_VERSION=8.28.0 \
    TRIVY_VERSION=0.74.0 \
    PIP_AUDIT_VERSION=2.9.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl tar \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/sechelix-runtime \
 && /opt/sechelix-runtime/bin/python -m pip install --no-cache-dir \
      "semgrep==${SEMGREP_VERSION}" \
      "pip-audit==${PIP_AUDIT_VERSION}"

RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) \
        gitleaks_asset="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
        gitleaks_sha="a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb"; \
        trivy_asset="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
        trivy_sha="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"; \
        ;; \
      arm64) \
        gitleaks_asset="gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"; \
        gitleaks_sha="eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356"; \
        trivy_asset="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"; \
        trivy_sha="b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5"; \
        ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gitleaks_asset}" -o /tmp/gitleaks.tgz; \
    echo "${gitleaks_sha}  /tmp/gitleaks.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tgz -C /opt/sechelix-runtime/bin gitleaks; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_asset}" -o /tmp/trivy.tgz; \
    echo "${trivy_sha}  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /opt/sechelix-runtime/bin trivy; \
    rm -f /tmp/gitleaks.tgz /tmp/trivy.tgz; \
    /opt/sechelix-runtime/bin/gitleaks version; \
    /opt/sechelix-runtime/bin/trivy --version; \
    /opt/sechelix-runtime/bin/semgrep --version; \
    /opt/sechelix-runtime/bin/pip-audit --version

FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

RUN useradd --create-home --uid 10001 sechelix

COPY --from=builder /opt/sechelix-runtime /opt/sechelix-runtime

ENV PATH="/opt/sechelix-runtime/bin:${PATH}"

USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/bin/env"]
