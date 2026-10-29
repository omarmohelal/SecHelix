# Full local installation: SecHelix + embedded Strix

This path installs the optional SecHelix runtime and the exact Strix engine
revision that passed SecHelix's compatibility contract.

## Recommended Windows setup

Use Windows 11 + WSL2 Ubuntu 24.04 + Docker Desktop with WSL integration enabled.
Ubuntu 24.04 ships Python 3.12, which satisfies both SecHelix and the pinned
Strix 1.6.2 engine.

In PowerShell as Administrator:

```powershell
wsl --install -d Ubuntu-24.04
```

After restart, open Ubuntu and install the small host prerequisites:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

Clone the full tree, including the embedded Strix engine:

```bash
git clone --recurse-submodules https://github.com/omarmohelal/SecHelix.git
cd SecHelix
bash scripts/bootstrap-full.sh
```

If the repository was cloned without submodules:

```bash
git submodule update --init --recursive
bash scripts/bootstrap-full.sh
```

## What "embedded Strix" means

Strix source lives at `engines/strix` inside the SecHelix checkout and is pinned
to the exact upstream commit recorded in `integrations/strix-compat.json`.
SecHelix installs that local source into the same virtual environment.

The source location does not weaken the architectural boundary:

```text
Strix engine -> CANDIDATE
               |
               v
SecHelix reproduction -> independent verifier -> VERIFIED / REJECTED / UNKNOWN
```

Strix cannot authorize a target, expand scope, promote its own result to
VERIFIED, accept its own fix, or make the release decision.

## OpenRouter

The tested Strix runtime uses LiteLLM provider/model identifiers. Configure
OpenRouter in the shell that launches SecHelix:

```bash
export STRIX_LLM="openrouter/z-ai/glm-5.3"
read -rsp "OpenRouter API key: " LLM_API_KEY
export LLM_API_KEY
echo
```

Do not commit the key to the repository.

Other OpenRouter routes can use the normal
`openrouter/<provider>/<model>` format. Model selection should eventually be
driven by the SecHelix benchmark/Nexus router rather than reputation alone.

Optional:

```bash
export STRIX_REASONING_EFFORT="high"
export STRIX_OPENROUTER_STICKY_SESSIONS="true"
```

## Health checks

```bash
source .venv/bin/activate
docker info
strix --version
sechelix doctor
sechelix-pentest engine-health
```

The Strix health result should report version `1.6.2` and
`compatibility: TESTED`.

## First local smoke test

Start an application you own locally, then from the SecHelix checkout:

```bash
source .venv/bin/activate

sechelix-pentest run http://127.0.0.1:3000   --mode local   --source-root /path/to/your/app   --tool strix   --executor nexus   --strix-scan-mode quick   --strix-max-turns 100   --strix-max-budget 2
```

If Nexus is not configured yet, use `--executor none` only as an integration
smoke test. Strix can still produce candidates, but SecHelix will correctly keep
reasoning/verification incomplete instead of manufacturing a clean result.

For a non-loopback target, use an explicit STAGING authorization/scope manifest.
Active production testing remains denied unless a separately implemented
production-safe procedure allows the exact operation.
