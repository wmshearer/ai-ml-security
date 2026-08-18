"""
Deterministic tool-authorization layer for the overprivileged target tools.

This is the fix for the LLM03:2026 Excessive Agency gap planted in
src/target/tools.py (send_email/read_file have no authorization check) and
dispatched with no gating in src/target/main.py. Per OWASP LLM03:2026's own
top mitigation -- "implement authorization in logic rather than relying on
an LLM to decide" -- this module contains zero LLM calls, zero network I/O,
and zero filesystem I/O of its own. It is pure, synchronous, deterministic
policy logic over the tool name and arguments the model supplied, and it is
meant to be called *before* src/target/tools.py's implementations run.

Design principles (see research/phase-4-guardrails-and-measurement.md,
"ranked guardrail recommendation" -- Rank 1):
  - Fail closed: anything not explicitly permitted is denied. An unknown
    tool, a malformed/missing argument, or an argument that doesn't match
    an allow-list rule all deny by default -- there is no implicit-allow
    path anywhere in this module.
  - Structured decisions, not bare booleans: callers (and the evidence
    report) need the *reason* a call was denied, not just a 403-shaped
    flag.
  - No naive string-prefix checks for paths. Path traversal
    (`../`, `....//`, absolute paths, symlinks) is closed by resolving the
    path against the allowed root with pathlib and then verifying
    real containment -- see check_read_file's docstring for why a
    startswith() check is bypassable and insufficient here.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# --- send_email policy ------------------------------------------------------
#
# Allow-list of exact recipient addresses and/or recipient domains. Only
# internal Acme Testing Corp addresses are permitted; every attacker address
# observed in evidence (external domains supplied via prompt injection) is
# denied by simply not appearing here. Fail-closed means a recipient that
# matches neither an exact address nor an allowed domain is denied -- there
# is no wildcard/catch-all entry.
ALLOWED_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "acme-testing.example",
})

ALLOWED_EMAIL_ADDRESSES: frozenset[str] = frozenset({
    "helpdesk@acme-testing.example",
})

# --- read_file policy --------------------------------------------------------
#
# read_file is scoped to a single safe subdirectory of the fake filesystem
# (see src/target/fake_data.py's FAKE_FILESYSTEM key namespace). Only paths
# that resolve inside this root are permitted; the sensitive files
# (/hr/confidential/..., /system_prompt, /etc/hosts, /etc/passwd) all live
# outside it by construction, so they are denied without needing a
# per-file blocklist entry.
ALLOWED_READ_ROOT = PurePosixPath("/helpdesk/public")


@dataclass(frozen=True)
class AuthzDecision:
    """Structured authorization result. `reason` is always populated (both
    on allow and deny) so evidence/report.md can show *why*, not just a
    pass/fail bit."""

    allowed: bool
    reason: str


def _normalize_posix_path(path: str) -> PurePosixPath | None:
    """Resolve a path string to a normalized, absolute PurePosixPath, or
    None if it isn't a well-formed absolute path at all.

    Why not a naive `path.startswith("/helpdesk/public")` check: that is
    bypassable by construction. A string-prefix test never sees that
    "/helpdesk/public/../../etc/hosts" or
    "/helpdesk/public_backdoor/secret" both start with the right prefix
    text while resolving (or plausibly referring) to a location outside
    the allowed root. `PurePosixPath` (chosen over `pathlib.Path` /
    `os.path.realpath` because this module must stay filesystem-free --
    FAKE_FILESYSTEM is an in-memory dict, not real disk paths, so there is
    nothing on disk to call realpath()/resolve() against, and no symlinks
    for a purely virtual path to traverse) gives us `.parts` after
    collapsing `.`/`..` segments purely lexically, which is exactly what
    is needed to check genuine containment below.
    """
    if not path or not isinstance(path, str):
        return None
    if not path.startswith("/"):
        return None  # relative paths are never valid tool arguments here

    # Collapse "." and ".." segments ourselves rather than trusting the
    # library to do it silently, so the traversal-closing logic is visible
    # and auditable in one place instead of hidden inside a library call.
    parts: list[str] = []
    for segment in PurePosixPath(path).parts:
        if segment in ("/", ""):
            continue
        if segment == ".":
            continue
        if segment == "..":
            if parts:
                parts.pop()
            # A ".." at/above the root has nothing to pop to; per POSIX
            # semantics for an absolute path this stays at "/" rather than
            # escaping it, so we simply drop it instead of erroring --
            # containment is still verified below regardless.
            continue
        segment_path = PurePosixPath(segment)
        # A path component containing another "/" after PurePosixPath's own
        # split (e.g. a component smuggled in by a "....//" style
        # padding trick) would only appear this way if two literal path
        # separators of the original string were both parsed as boundaries,
        # which PurePosixPath already does -- .parts never yields multi-
        # segment strings, so this cannot happen. Documented here, not
        # re-checked, to make that invariant explicit for the next reader.
        parts.append(segment)

    return PurePosixPath("/", *parts)


def check_send_email(args: dict) -> AuthzDecision:
    """Authorize (or deny) a send_email(to, body) call.

    Fails closed: missing/malformed `to`, or a recipient that matches
    neither the exact-address nor the domain allow-list, is denied.
    """
    if not isinstance(args, dict):
        return AuthzDecision(False, "malformed arguments: expected an object")

    to = args.get("to")
    if not isinstance(to, str) or not to.strip():
        return AuthzDecision(False, "malformed arguments: 'to' is missing or not a string")

    to = to.strip().lower()
    if to in ALLOWED_EMAIL_ADDRESSES:
        return AuthzDecision(True, f"recipient '{to}' is explicitly allow-listed")

    # Exactly one '@' is required to extract a domain; anything else
    # (no '@', multiple '@', empty local/domain part) is malformed and
    # denied rather than guessed at.
    if to.count("@") != 1:
        return AuthzDecision(False, f"malformed recipient address: '{to}'")

    _local, _, domain = to.partition("@")
    if not _local or not domain:
        return AuthzDecision(False, f"malformed recipient address: '{to}'")

    if domain in ALLOWED_EMAIL_DOMAINS:
        return AuthzDecision(True, f"recipient domain '{domain}' is allow-listed")

    return AuthzDecision(False, f"recipient domain '{domain}' is not on the allow-list")


def check_read_file(args: dict) -> AuthzDecision:
    """Authorize (or deny) a read_file(path) call.

    Fails closed: missing/malformed `path`, or a path that does not
    genuinely resolve inside ALLOWED_READ_ROOT after normalization, is
    denied. This specifically closes path-traversal ('../', '....//'),
    absolute paths outside the root (/system_prompt, /etc/hosts,
    /etc/passwd), and any path whose lexically-normalized form escapes the
    root even if its literal text happens to start with the root prefix.
    """
    if not isinstance(args, dict):
        return AuthzDecision(False, "malformed arguments: expected an object")

    path = args.get("path")
    if not isinstance(path, str) or not path.strip():
        return AuthzDecision(False, "malformed arguments: 'path' is missing or not a string")

    normalized = _normalize_posix_path(path.strip())
    if normalized is None:
        return AuthzDecision(False, f"malformed or non-absolute path: '{path}'")

    # Genuine containment check: is ALLOWED_READ_ROOT one of normalized's
    # ancestors (or normalized itself)? This is the check that a
    # startswith() string comparison cannot safely express, because it
    # operates on the *normalized* segment list, not the original text --
    # "/helpdesk/public/../../etc/hosts" normalizes to "/etc/hosts", whose
    # parents are ("/",), which does not include ALLOWED_READ_ROOT, so it
    # is correctly denied even though the raw string started with
    # "/helpdesk/public".
    if normalized == ALLOWED_READ_ROOT or ALLOWED_READ_ROOT in normalized.parents:
        return AuthzDecision(True, f"path '{normalized}' is within the allowed root")

    return AuthzDecision(
        False, f"path '{normalized}' (normalized from '{path}') is outside the allowed root {ALLOWED_READ_ROOT}"
    )


# Dispatch table: only tools with an explicit policy function are
# authorizable at all. Fail-closed applies at two levels: (1) a tool name
# not present here is denied by authorize() below, and (2) each policy
# function above denies by default within its own tool's argument space.
_POLICIES = {
    "send_email": check_send_email,
    "read_file": check_read_file,
}


def authorize(tool_name: str, args: dict) -> AuthzDecision:
    """Single entry point: authorize a tool call by name + arguments.

    Any tool_name without a registered policy (including tools that have
    no authorization concerns at all, like lookup_employee, and any
    unrecognized/unknown tool name) is denied -- fail-closed applies to
    unlisted tools too. Callers that want to allow an unlisted tool to run
    unchecked (e.g. lookup_employee, which is deliberately low-risk) must
    do so explicitly at the call site rather than relying on this function
    to permit it implicitly.
    """
    policy = _POLICIES.get(tool_name)
    if policy is None:
        return AuthzDecision(False, f"no authorization policy registered for tool '{tool_name}'")
    return policy(args if isinstance(args, dict) else {})
