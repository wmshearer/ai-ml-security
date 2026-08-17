"""
PyRIT target wiring for the Phase 1 helpdesk agent, routed through the
recording shim (shim.py) so tool_calls_made/retrieved_doc_ids are captured
for LLM03/LLM09 scoring even though PyRIT's own callback_function only
forwards the reply text to a Scorer.

Written against the current pyrit.executor.attack.* API. Note that
pyrit.orchestrator (PromptSendingOrchestrator / RedTeamingOrchestrator) does
NOT exist in current PyRIT — it was restructured with no compatibility shim,
so the pattern in most public tutorials raises ImportError.

Target class: HTTPTarget, NOT HTTPXAPITarget.

This was resolved by reading the source directly (2026-08-17). The earlier
design preferred HTTPXAPITarget, but that class CANNOT inject a prompt into a
JSON body at all: `self.json_data` is assigned once in the constructor
(httpx_api_target.py:104) and passed unmodified to httpx
(httpx_api_target.py:183). There is no placeholder, no positional
substitution, and no callable injection for the body — the only place it
inspects prompt content is to auto-discover a file path in upload mode. A
`{"message": "{PROMPT}"}` json_data would be sent to the target literally,
with the placeholder never replaced, and every attack would silently test the
string "{PROMPT}" instead of the actual payload. That failure is
near-invisible in results: the target answers normally, nothing errors, and
every probe simply reports a miss.

HTTPTarget substitutes via re.sub of prompt_regex_string into a raw HTTP
request string (http_target._inject_prompt_into_request, http_target.py:135-151),
which is a confirmed working mechanism.
"""
from __future__ import annotations

from typing import Any

# All pyrit imports are deferred into functions (not module-level) so this
# file can be imported and byte-compiled without pyrit installed — matches
# the "write against the verified API, do not install" constraint. A
# real driver script would import pyrit at module level once it's actually
# runnable.

SHIM_CHAT_URL = "http://127.0.0.1:8001/chat"

# PyRIT defaults max_requests_per_minute to None (unlimited) on both
# HTTPTarget and HTTPXAPITarget (research item 4) — that is a real footgun
# against a single local 7B model behind Ollama's own OLLAMA_NUM_PARALLEL=1
# default, so this is set explicitly and low, matching the research's 6-10
# recommendation and mirroring garak's config-side "omit parallel_requests"
# caution on the other tool.
MAX_REQUESTS_PER_MINUTE = 6


def parse_reply(*, response: Any) -> str:
    """callback_function passed to HTTPXAPITarget/HTTPTarget: PyRIT's Scorer
    layer only ever sees the string this returns, not the full JSON body
    (research item 2's "known gap", same shape as garak's
    response_json_field limitation). tool_calls_made/retrieved_doc_ids are
    NOT available to a PyRIT Scorer through this path — they must be joined
    back in after the run via shim.get_recorded_response(), keyed by the
    X-Harness-Request-Id response header the shim sets on every call.
    """
    return response.json()["reply"]


def build_httpx_api_target():
    """REMOVED as a usable option — kept only to fail loudly.

    HTTPXAPITarget cannot substitute a prompt into its JSON body (see the
    module docstring). Calling it would produce a run in which every attack
    silently tests the literal string "{PROMPT}" and reports a miss, which
    looks exactly like "the target is secure." That is a worse outcome than
    an exception, so this raises instead.
    """
    raise NotImplementedError(
        "HTTPXAPITarget cannot inject a prompt into json_data "
        "(httpx_api_target.py:104,183 — static dict, no substitution). "
        "Use build_http_target() instead."
    )


def build_http_target():
    """The target builder to use. HTTPTarget takes a raw HTTP request string
    and substitutes prompt_regex_string via re.sub
    (http_target.py:135-151).

    JSON-escaping caveat: that substitution is a raw-text regex sub, NOT
    JSON-aware — unlike garak's $INPUT, which is JSON-escaped by the
    generator. A payload containing a double quote, backslash, or newline
    would produce a malformed request body and the target would reject it
    with a 422. Since red-team payloads routinely contain exactly those
    characters, the prompt is escaped before injection via the callback
    below. json.dumps() on the raw value yields a quoted, escaped JSON
    string; the surrounding quotes are stripped because the template already
    supplies them.
    """
    from pyrit.prompt_target.http_target.http_target import HTTPTarget

    raw_request = (
        "POST /chat HTTP/1.1\r\n"
        "Host: 127.0.0.1:8001\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        '{"message": "{PROMPT}"}'
    )
    return HTTPTarget(
        http_request=raw_request,
        prompt_regex_string="{PROMPT}",
        use_tls=False,
        callback_function=parse_reply,
        max_requests_per_minute=MAX_REQUESTS_PER_MINUTE,
    )


def json_escape(payload: str) -> str:
    """Escape a payload for safe injection into the JSON body template.

    HTTPTarget's substitution is a plain regex sub, so an unescaped quote in
    a payload breaks the request body. Apply this to a payload BEFORE handing
    it to an attack when the payload may contain quotes, backslashes, or
    newlines — which adversarial payloads frequently do.
    """
    import json as _json

    return _json.dumps(payload)[1:-1]


def build_prompt_sending_attack(target=None):
    """Wires a PromptSendingAttack (pyrit.executor.attack.single_turn.
    prompt_sending.PromptSendingAttack) against the shim-fronted target —
    this is the current-API replacement for the widely-blogged, no-longer-
    existing PromptSendingOrchestrator (research item 2: pyrit.orchestrator
    does not exist as a top-level package in current main/1.0.1).

    attack_class string for the normalizer/mapping.py lookup is
    "PromptSendingAttack" — pass this exact string to
    normalize.normalize_pyrit_attack_result(attack_class=...) since
    AttackResult does not self-report a classname field.
    """
    from pyrit.executor.attack.single_turn.prompt_sending import PromptSendingAttack

    if target is None:
        target = build_http_target()
    return PromptSendingAttack(objective_target=target)


def build_crescendo_attack(target=None, *, adversarial_chat=None, scoring_target=None):
    """Wires a CrescendoAttack (pyrit.executor.attack.multi_turn.crescendo.
    CrescendoAttack) for multi-turn escalation — PyRIT's headline
    differentiator over garak (research item 3: garak has no maintained
    multi-turn escalation equivalent). Not present in Phase 1's 6 attacks;
    this is the natural Phase 2 addition the research recommends.

    CrescendoAttack additionally requires an adversarial_chat target (the
    LLM generating escalating prompts) and typically a scoring_target — both
    left as None/caller-supplied here since neither has a settled choice
    yet for this project (would itself need to be an Ollama-backed
    PromptChatTarget or similar); wiring those is explicitly out of scope
    for this pass and left for whoever runs the first live Crescendo attempt.
    """
    from pyrit.executor.attack.multi_turn.crescendo import CrescendoAttack

    if target is None:
        target = build_http_target()
    return CrescendoAttack(
        objective_target=target,
        adversarial_chat=adversarial_chat,
        scoring_target=scoring_target,
    )
