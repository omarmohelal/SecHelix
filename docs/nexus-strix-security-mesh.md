# Nexus + SecHelix + Strix security mesh

This integration keeps the three responsibilities separate:

- **Nexus** is the engineering orchestrator: provider selection, retries, checkpoints, cost/accounting, implementation and review.
- **SecHelix** is the security control plane and evidence authority: scope, candidate/verified states, independent verification, remediation/regression and release gates.
- **Strix** is a replaceable active-testing engine behind SecHelix scope and evidence gates. Its output is untrusted scanner evidence until SecHelix verifies it.

## Current Strix model routing

Upstream Strix uses LiteLLM and can route to many providers. The current upstream documentation uses
`openrouter/z-ai/glm-5.3` as the default example/recommendation and also lists OpenAI, Anthropic,
Gemini, DeepSeek, Qwen and Kimi families.

Do not hard-code one "best hacking model". Security roles are selected by measured fixture performance,
cost, tool reliability and provider independence. A security-tuned model can be a hunter; the verifier
should preferably use a different provider/model family.

## Recommended operator topology

For the owner's current cost-sensitive setup:

1. **Routine engineering / cheap analysis**: existing Nexus plan lanes and CheaperInference credit.
2. **Strix default active reasoning**: OpenRouter GLM-5.3, because this matches current Strix upstream guidance and gives provider failover.
3. **Security-specialist alternate hunter**: Routeway GLM-5.3 Flash Cybersecurity or Qwen3.8-27B Cybersecurity.
4. **Independent verifier**: Nexus `review` role on a different family/provider when practical (for example Codex/Claude/Gemini/HF review when available).
5. **Uncensored/abliterated models**: optional authorized-lab fallback only; they are never treated as evidence and never bypass SecHelix scope/tool gates.

## Preferred setup when FCC already owns the provider accounts

If FCC already has OpenRouter, CheaperInference, Hugging Face, MiniMax, Z.ai, OpenAI and other
providers configured, do **not** copy those provider API keys into Nexus or SecHelix.

Use FCC as the loopback credential/model gateway:

```powershell
$env:SECHELIX_STRIX_USE_FCC="1"
$env:FCC_BASE_URL="http://127.0.0.1:8082/v1"
$env:SECHELIX_STRIX_FCC_MODEL="<exact FCC model id>"
```

SecHelix then launches Strix with the FCC model id, points it at the loopback FCC endpoint and forces
the OpenAI Responses wire format. The underlying OpenRouter/DeepSeek/HF/etc. credentials stay inside
FCC. If the local FCC gateway itself requires a bearer token, place only that local gateway token in
`SECHELIX_PENTEST_FCC_API_KEY`; never copy the upstream provider keys.

This mode is accepted only for loopback FCC URLs. A remote FCC URL is refused by default so a model
prompt or local gateway credential cannot silently leave the machine.

FCC must still prove that the selected model supports the tool-calling/structured-output behavior
Strix needs. Catalog presence alone is not proof; run a harmless authorized fixture before promotion.

## Remote Strix credential isolation

The pentest worker does **not** inherit generic host API keys. Give Strix one dedicated worker secret:

```bash
export STRIX_LLM="openrouter/z-ai/glm-5.3"
export LLM_API_BASE="https://openrouter.ai/api/v1"
export SECHELIX_PENTEST_STRIX_API_KEY="<provider key>"
```

The worker maps `SECHELIX_PENTEST_STRIX_API_KEY` to `LLM_API_KEY` only inside the isolated job
environment when `STRIX_LLM` is configured. The source secret name is removed from that child
environment. Unrelated OpenAI/Anthropic/provider keys are not forwarded.

For an OpenAI-compatible Routeway security endpoint:

```bash
export STRIX_LLM="openai/glm-5.3-flash-cybersecurity"
export LLM_API_BASE="https://api.routeway.ai/v1"
export SECHELIX_PENTEST_STRIX_API_KEY="<routeway key>"
export STRIX_FORCE_API="chat_completions"
```

Use the exact model identifier supported by the selected gateway. Probe a low-risk authorized fixture
before relying on a route in production.

## Nexus executor

SecHelix can use `--executor nexus` for provider-neutral reasoning nodes. The worker permits this
executor without importing Nexus provider credentials into SecHelix. Nexus keeps provider auth in its
own CLI/runtime stores.

Independent verification is routed through Nexus's `review` role, not the hunter's
`security-engineer` role. Set `SECHELIX_NEXUS_VERIFIER_LANE` only when the operator wants a specific
independent lane.

## Acceptance

Before calling this mesh ready:

- Strix compatibility check passes for the pinned/tested upstream contract.
- One low-risk vulnerable fixture is found and normalized as a candidate.
- The clean sibling is not promoted to a verified finding.
- An independent verifier can refute or reconstruct the candidate from evidence.
- Provider failure does not lose SecHelix run state.
- No raw provider secret appears in reports, logs, checkpoints or Nexus/SecHelix memory.
- Remediation is followed by regression and retest.
