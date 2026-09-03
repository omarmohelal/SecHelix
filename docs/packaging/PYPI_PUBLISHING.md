# PyPI trusted publishing

SecHelix publishes the optional Python evidence runtime separately from the Agent Skill. The Python project name is `sechelix`; the package version is defined by `pyproject.toml` and is intentionally independent from the Agent Skill/plugin release version.

## Security model

`.github/workflows/publish-pypi.yml` uses PyPI Trusted Publishing (GitHub OIDC). It stores no PyPI username, password, or long-lived API token in GitHub.

The workflow is deliberately manual and fail closed:

1. the operator must enter the exact package version;
2. the build job checks out `main`, not the caller's branch;
3. runner/package tests must pass;
4. wheel and sdist are built in CI;
5. the wheel is installed into a fresh virtual environment and `sechelix doctor --json` must confirm bundled core contracts;
6. only the verified distribution artifacts cross into the publish job;
7. only the publish job receives `id-token: write`;
8. the `pypi` GitHub environment is the approval boundary;
9. the PyPI publishing action is pinned to an immutable commit.

A failed, mismatched, or unconfigured run must not fall back to an API token.

## One-time external setup

The repository side is complete. Before the first upload, configure a PyPI Trusted Publisher (or Pending Trusted Publisher if the `sechelix` PyPI project does not exist yet) with exactly:

- **PyPI project:** `sechelix`
- **GitHub owner:** `omarmohelal`
- **GitHub repository:** `SecHelix`
- **Workflow:** `publish-pypi.yml`
- **Environment:** `pypi`

On GitHub, create the `pypi` environment and require a trusted maintainer approval before deployment. Do not add a PyPI API token secret as a fallback.

A Pending Trusted Publisher does not reserve the project name until the first successful upload, so complete the first publication promptly after configuring it.

## Publishing

From GitHub Actions, run **Publish runner to PyPI** and enter the exact current `pyproject.toml` version (currently `0.1.0`). Approve the `pypi` environment only after the build job is green and the displayed version is the intended one.

After publishing, verify from a clean environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install sechelix==0.1.0
sechelix doctor --json
```

The installed runtime should report its core contracts present. A PyPI upload is distribution evidence, not a security-quality or benchmark claim.
