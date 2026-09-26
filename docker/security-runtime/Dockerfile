# SecHelix V5 static security-tool runtime recipe.
#
# This image is source-reproducible at the container/source level:
# - every parent/tool image is referenced by immutable digest;
# - Python tools are exact-version pinned;
# - no scanner DB is fetched at runtime by this recipe;
# - runtime egress remains disabled by SandboxSpec / SandboxRunner.
#
# A published SecHelix image digest is intentionally NOT invented here. Build,
# scan and publish this recipe first, then configure the resulting immutable
# image reference where the runtime is consumed.

FROM ghcr.io/gitleaks/gitleaks@sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854 AS gitleaks
FROM ghcr.io/aquasecurity/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 AS trivy

# Same digest-pinned Python base used by the public SecHelix container.
FROM python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS runtime

ARG SEMGREP_VERSION=1.140.0
ARG PIP_AUDIT_VERSION=2.9.0
ARG TRIVY_VERSION=0.74.0
ARG GITLEAKS_VERSION=8.28.0

RUN python -m pip install --no-cache-dir --disable-pip-version-check \
    "semgrep==${SEMGREP_VERSION}" \
    "pip-audit==${PIP_AUDIT_VERSION}"

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# Build-time verification prevents a stale digest/binary mismatch from being
# silently described as the declared runtime inventory.
RUN semgrep --version | grep -F "${SEMGREP_VERSION}" \
 && pip-audit --version | grep -F "${PIP_AUDIT_VERSION}" \
 && trivy --version | grep -F "Version: ${TRIVY_VERSION}" \
 && gitleaks version | grep -F "${GITLEAKS_VERSION}"

RUN useradd --create-home --uid 10001 sechelix
USER sechelix
WORKDIR /workspace

# The image deliberately has no entrypoint: model/agent code never receives a
# generic shell surface. Named SecHelix adapters select exact executables.
CMD ["python", "-c", "raise SystemExit('select a named SecHelix tool capability')"]
