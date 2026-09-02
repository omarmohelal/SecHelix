# Publishing the `sechelix` runner to PyPI

Everything up to the upload is automated and verified. The upload itself needs a
credential this session does not have, so it is left as one explicit human step.

## State

| | |
|---|---|
| PyPI name `sechelix` | **available** (checked: `GET /pypi/sechelix/json` → 404) |
| Wheel | builds, 366 KB, 80 files |
| sdist | builds |
| Clean-venv install | verified — `sechelix doctor` exits 0 with `core_contracts: True` |
| Runtime dependencies | none, asserted by a test |
| Upload | **blocked on a PyPI API token** |

## What ships

`sechelix_runner`, `sechelix_core`, and the `schemas/` + `catalog/` JSON bundled
under `sechelix_runner/_bundled/`. The Agent Skill itself is **not** in the
wheel — it is distributed through the skills ecosystem:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

## Build and verify

```bash
rm -rf dist build
python -m build
python -m twine check dist/*

# prove it installs clean
python -m venv /tmp/v && /tmp/v/bin/pip install dist/sechelix-*.whl
/tmp/v/bin/sechelix doctor .      # must print core_contracts: True and exit 0
```

## The one human step

Publishing needs a PyPI account and an API token. Neither is available to an
automated session, and creating an account requires accepting terms on someone's
behalf — which is not something to automate.

```bash
# 1. Create the token at https://pypi.org/manage/account/token/
#    Scope it to the `sechelix` project after the first upload.

# 2. Upload to TestPyPI first and install from there to confirm the metadata:
python -m twine upload --repository testpypi dist/*
pipx install --index-url https://test.pypi.org/simple/ sechelix

# 3. Then the real index:
python -m twine upload dist/*
```

After the first successful upload:

```bash
pipx install sechelix      # or: uv tool install sechelix
sechelix doctor
```

## Version policy

The package version (`0.1.0`) tracks the **runner**, not the SecHelix
methodology version (`3.4.0-alpha.2`). They move independently: the runner can
ship a bug fix without the catalog changing, and the catalog is the versioned
artifact with its own validator.
