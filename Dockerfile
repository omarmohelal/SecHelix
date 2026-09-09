# Run the SecHelix MCP adapter in a container.
#
# The adapter reads a tree it does not trust, so a container is a second
# boundary around it -- not a replacement for the server's own. The enforced
# boundary is still the configured root: every path argument any tool receives
# is resolved and refused if it lands outside /workspace.
#
#   docker build -t sechelix .
#   docker run --rm -i --network none -v "$PWD:/workspace" sechelix
#
# Wire it into an MCP client as:
#   command: docker
#   args: ["run","--rm","-i","--network","none","-v","/abs/path:/workspace","sechelix"]
#
# On `:ro` -- two things worth knowing before you add it:
#
#   * `sechelix_audit` writes a run workspace under the root, so a read-only
#     mount leaves you with the six read-only tools and an audit tool that
#     fails. That is a reasonable trade if you only want to read recorded runs.
#   * `:ro` is enforced by the host's bind-mount implementation, not by this
#     image. Verified on Docker Desktop for Windows (29.6.2): a write to a
#     `:ro` bind mount **succeeded**. Do not rely on it as the boundary.
#
# Pinned by digest so a rebuild cannot silently change the base image.
FROM python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS base

# The runner declares no dependencies, so this installs exactly one package.
ARG SECHELIX_VERSION=0.3.0
RUN python -m pip install --no-cache-dir --disable-pip-version-check "sechelix==${SECHELIX_VERSION}"

# Never run a code-review tool as root.
RUN useradd --create-home --uid 10001 sechelix
USER sechelix
WORKDIR /workspace

# stdio transport: the client speaks JSON-RPC over stdin and stdout.
ENTRYPOINT ["sechelix", "mcp", "/workspace"]
