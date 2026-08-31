# Security policy

## Reporting a SecHelix vulnerability

Please do not publish an unpatched vulnerability in SecHelix itself as a public issue if it could enable unsafe behavior in users' environments.

Open a minimal issue only if no sensitive detail is required, or contact the maintainer privately through the contact method published on the project website once configured.

Include:

- affected version/commit;
- affected file/path;
- threat model and prerequisites;
- safe reproduction;
- impact;
- suggested mitigation if known.

## Scope of the project

SecHelix is an application-security **methodology and skill bundle** for authorized targets. It is not intended for unauthorized exploitation, credential theft, persistence, malware deployment, denial of service, destructive payload execution, or indiscriminate internet scanning.

## Safe defaults

SecHelix defaults to static/local evidence. Production testing should remain non-destructive unless an operator explicitly authorizes a narrowly bounded action in an environment they control.

## Dependency / website security

The landing page is intentionally static and dependency-light. Future integrations that introduce packages, webhooks, hosted services, payment widgets, or telemetry must be threat-modeled and documented.

## Supported versions

Until the project reaches a stable 1.0 public API, security fixes target the latest release and `main`.