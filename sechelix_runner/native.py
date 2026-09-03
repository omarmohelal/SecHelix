"""Native/memory-safety source-review lane for C, C++ and Rust.

This is not a binary exploitation engine.  It observes source constructs that
change the review question -- unsafe memory APIs, FFI boundaries, parser length
arithmetic, command execution and legacy crypto -- and emits CANDIDATE signals.
No signal is a vulnerability until a specialist establishes attacker control,
reachability, the failed invariant and impact.

The lane is applicability-gated by file suffix and bounded by file/byte limits
so adding a native dependency does not turn every SecHelix run into an
unbounded source scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


_NATIVE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".rs"}


@dataclass(frozen=True, slots=True)
class NativePattern:
    pattern_id: str
    languages: tuple[str, ...]
    expression: re.Pattern[str]
    observation: str
    review_question: str
    false_positive_filter: str


@dataclass(frozen=True, slots=True)
class NativeSignal:
    signal_id: str
    pattern_id: str
    language: str
    path: str
    line: int
    observation: str
    review_question: str
    false_positive_filter: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "sechelix-native-signal/v1",
            "signal_id": self.signal_id,
            "status": "CANDIDATE",
            "assessment": "UNASSESSED",
            "severity": "UNASSESSED",
            "pattern_id": self.pattern_id,
            "language": self.language,
            "path": self.path,
            "line": self.line,
            "observation": self.observation,
            "review_question": self.review_question,
            "false_positive_filter": self.false_positive_filter,
        }


def _rx(value: str) -> re.Pattern[str]:
    return re.compile(value)


PATTERNS: tuple[NativePattern, ...] = (
    NativePattern(
        "NATIVE-C-UNBOUNDED-COPY",
        ("C", "C++"),
        _rx(r"\b(strcpy|strcat|sprintf|gets)\s*\("),
        "legacy unbounded string/memory API appears in native source",
        "Can attacker-controlled length/content reach the destination without a capacity invariant?",
        "The source has a statically proven bound smaller than the destination, or the call is unreachable from untrusted input.",
    ),
    NativePattern(
        "NATIVE-C-MEMORY-LENGTH",
        ("C", "C++"),
        _rx(r"\b(memcpy|memmove|read|recv|fread)\s*\("),
        "explicit byte-count memory/input API appears in native source",
        "Where does the length come from, what is the destination capacity, and are integer conversions checked before the operation?",
        "Length is derived from destination capacity or validated through a dominating invariant evidenced on this path.",
    ),
    NativePattern(
        "NATIVE-C-COMMAND",
        ("C", "C++"),
        _rx(r"\b(system|popen|execl|execv|execve|CreateProcess[A-W]?)\s*\("),
        "process/command execution API appears in native source",
        "Can untrusted data influence executable, arguments, shell parsing or environment at this call?",
        "Executable/arguments are fixed or selected from a strict allowlist and no shell interpreter receives attacker-controlled text.",
    ),
    NativePattern(
        "NATIVE-C-FORMAT",
        ("C", "C++"),
        _rx(r"\b(printf|fprintf|syslog)\s*\([^,\n]*\)"),
        "format-capable output call appears with a shape worth checking",
        "Is the format string constant, or can attacker-controlled text become the format rather than a value argument?",
        "The format is a constant and all untrusted values are passed through value placeholders.",
    ),
    NativePattern(
        "NATIVE-RUST-UNSAFE",
        ("Rust",),
        _rx(r"\bunsafe\s*(\{|fn\b|impl\b|trait\b)"),
        "Rust unsafe boundary appears in source",
        "Which memory/lifetime/aliasing invariant is the unsafe block assuming, and can safe callers violate it with untrusted sizes or states?",
        "Unsafe block is encapsulated behind a safe API whose preconditions are enforced before entry and covered by tests/Miri where applicable.",
    ),
    NativePattern(
        "NATIVE-RUST-RAW",
        ("Rust",),
        _rx(r"\b(from_raw_parts|from_raw_parts_mut|transmute|read_unaligned|write_unaligned|copy_nonoverlapping)\b"),
        "raw-memory primitive appears in Rust source",
        "Are pointer validity, alignment, initialized length and ownership invariants established before the primitive?",
        "All unsafe preconditions are proven from local bounds/ownership, not assumed from caller-provided metadata.",
    ),
    NativePattern(
        "NATIVE-FFI",
        ("C", "C++", "Rust"),
        _rx(r"\b(extern\s+\"C\"|FFI|ffi_|cbindgen|bindgen)\b"),
        "foreign-function boundary appears in native source",
        "What validates lengths, ownership, encoding and lifetime when data crosses the language boundary?",
        "Generated/handwritten bindings preserve explicit length/ownership contracts and both sides enforce the same representation.",
    ),
    NativePattern(
        "NATIVE-LEGACY-CRYPTO",
        ("C", "C++", "Rust"),
        _rx(r"\b(MD5|SHA1|RC4|DES_|EVP_md5|EVP_sha1)\b"),
        "legacy cryptographic primitive name appears in native source",
        "Is this primitive protecting a security property that requires collision/preimage/confidentiality strength, or only non-security compatibility?",
        "Use is non-security (for example a protocol checksum/legacy identifier) or a modern construction wraps it under an externally mandated compatibility boundary.",
    ),
)


def language_for(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix == ".rs":
        return "Rust"
    if suffix in {".c", ".h"}:
        return "C"
    if suffix in {".cc", ".cpp", ".cxx", ".hpp", ".hh"}:
        return "C++"
    return None


def scan_native_sources(
    root: Path | str,
    paths: Iterable[str] | None = None,
    *,
    max_files: int = 400,
    max_bytes_per_file: int = 512_000,
) -> list[NativeSignal]:
    """Return bounded candidate signals from applicable native source files."""
    root = Path(root).resolve()
    if not root.is_dir():
        return []
    selected = list(paths) if paths is not None else [
        str(path.relative_to(root)).replace("\\", "/")
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in _NATIVE_SUFFIXES
    ]
    signals: list[NativeSignal] = []
    for rel in sorted(selected)[:max_files]:
        path = (root / rel).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            continue
        language = language_for(path)
        if language is None:
            continue
        try:
            if path.stat().st_size > max_bytes_per_file:
                continue
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            # Comments are deliberately not stripped with a fake parser; a
            # match in a comment is still only a CANDIDATE and the specialist
            # can refute it. This avoids a half-parser silently deleting code.
            for pattern in PATTERNS:
                if language not in pattern.languages or not pattern.expression.search(line):
                    continue
                signal_id = f"NS-{pattern.pattern_id}-{len(signals) + 1:05d}"
                signals.append(
                    NativeSignal(
                        signal_id,
                        pattern.pattern_id,
                        language,
                        rel.replace("\\", "/"),
                        line_no,
                        pattern.observation,
                        pattern.review_question,
                        pattern.false_positive_filter,
                    )
                )
    return signals


def native_lane(root: Path | str, world: dict[str, Any]) -> dict[str, Any]:
    sources = list(world.get("native_sources", []))
    if not sources:
        return {
            "schema_version": "sechelix-native-lane/v1",
            "applicability": "NOT_APPLICABLE",
            "reason": "no C/C++/Rust source files observed in the bounded repository map",
            "signals": [],
        }
    signals = scan_native_sources(root, sources)
    return {
        "schema_version": "sechelix-native-lane/v1",
        "applicability": "APPLICABLE",
        "source_files": len(sources),
        "signals": [signal.to_dict() for signal in signals],
        "claim_boundary": "signals route review questions; none is a vulnerability verdict",
    }
