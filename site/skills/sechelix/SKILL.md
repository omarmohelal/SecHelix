---
name: sechelix
description: Evidence-first application-security audit workflow for authorized repositories and environments. Use for codebase, API, web, auth/authz, business-logic, payment, race-condition, supply-chain, AI/MCP, cloud, and release-security review.
---

# SecHelix web skill

Canonical source: https://github.com/omarmohelal/SecHelix/blob/main/SKILL.md

Use SecHelix only for systems you own or are explicitly authorized to test.

Core workflow:

1. establish scope and execution mode;
2. map architecture, identities, assets and trust boundaries;
3. select applicable hypotheses from the SecHelix catalog;
4. run specialist review lanes where useful;
5. treat scanner/model output as hypotheses;
6. independently verify High/Critical candidates;
7. repair canonical root causes;
8. add regression proof;
9. run the appropriate release gate;
10. report uncertainty and residual risk honestly.

Do not use destructive verification, uncontrolled internet scanning, credential theft, persistence, denial of service, malware, or data exfiltration.

For the full methodology and resources, use the canonical repository.