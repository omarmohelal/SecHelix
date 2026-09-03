from pathlib import Path

proof = Path("sechelix_runner/proof_exec.py")
text = proof.read_text(encoding="utf-8")
text = text.replace("import hashlib\nimport json\n", "import hashlib\nimport http.client\nimport json\n")
text = text.replace("import urllib.error\n", "")
text = text.replace("import urllib.request\n", "")
text = text.replace(
    "from .sandbox import ExecutionMode, NetworkPolicy, is_loopback\n",
    "from .sandbox import ExecutionMode, NetworkPolicy\n",
)

redirect_start = text.find("class _NoRedirect(")
callback_start = text.find("class _CallbackHandler", redirect_start)
if redirect_start != -1 and callback_start != -1:
    text = text[:redirect_start] + text[callback_start:]

request_method = text.index("    def _request(")
transport_start = text.index("        host = parsed.hostname\n", request_method)
transport_end = text.index("        elapsed = int(", transport_start)
replacement = '''        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.username is not None or parsed.password is not None:
            raise ProofExecutionError("proof URL must not contain user-info credentials")

        # LOCAL proof execution has no reason to cross a DNS trust boundary.
        # Select a constant connect host so DNS rebinding, ambient proxies and
        # redirect-following cannot turn a bounded proof into arbitrary egress.
        if host == "127.0.0.1":
            connect_host = "127.0.0.1"
        elif host == "::1":
            connect_host = "::1"
        else:
            raise ProofExecutionError(
                f"LOCAL proof target must use literal loopback 127.0.0.1 or ::1, got {host!r}"
            )
        self.policy.require(connect_host, port, protocol=parsed.scheme)
        self._requests += 1

        request_target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(connect_host, port, timeout=self.timeout_seconds)
        started = time.monotonic()
        status: int | None = None
        response_body = b""
        error = ""
        try:
            connection.request(
                method.upper(),
                request_target,
                body=body if method.upper() not in ("GET", "HEAD") else None,
                headers=dict(headers or {}),
            )
            response = connection.getresponse()
            status = int(response.status)
            response_body = response.read(262_144)
        except (http.client.HTTPException, TimeoutError, OSError) as exc:
            error = type(exc).__name__
        finally:
            connection.close()
'''
text = text[:transport_start] + replacement + text[transport_end:]
proof.write_text(text, encoding="utf-8")

optionality = Path("tests/runner/test_optionality.py")
ot = optionality.read_text(encoding="utf-8")
needle = '            "subprocess", "tempfile", "textwrap", "math", "copy", "abc", "functools",\n'
if '"concurrent"' not in ot:
    if needle not in ot:
        raise SystemExit("optionality allowlist insertion point not found")
    ot = ot.replace(needle, needle + '            "concurrent",\n')
optionality.write_text(ot, encoding="utf-8")

tests = Path("tests/runner/test_proof_exec.py")
tt = tests.read_text(encoding="utf-8")
if "test_local_executor_refuses_dns_names_even_when_they_resolve_to_loopback" not in tt:
    marker = '\n\nif __name__ == "__main__":\n'
    if marker not in tt:
        raise SystemExit("proof test insertion point not found")
    addition = '''

    def test_local_executor_refuses_dns_names_even_when_they_resolve_to_loopback(self) -> None:
        plan = build_plan(
            ProofClass.PATH_TRAVERSAL,
            "F-LOCALHOST",
            available_authority={"fixture_filesystem"},
        )
        with self.assertRaises(ProofExecutionError):
            self.executor.execute(
                plan,
                TraversalHttpSpec(
                    url_template=f"http://localhost:{self.port}/files?path={{path}}",
                    safe_path="safe",
                    traversal_path="../sentinel",
                    sentinel_marker=b"x",
                ),
            )
'''
    tt = tt.replace(marker, addition + marker)
tests.write_text(tt, encoding="utf-8")
