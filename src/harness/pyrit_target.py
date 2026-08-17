"""
PyRIT target wiring for the Phase 1 helpdesk agent, routed through the
recording shim (shim.py) so tool_calls_made/retrieved_doc_ids are captured
for LLM03/LLM09 scoring even though PyRIT's own callback_function only
forwards the reply text to a Scorer.

pyrit is NOT installed in this environment (confirmed: `pip show pyrit` ->
not found, per the research brief and re-confirmed before writing this
file). This module is written against the current pyrit.executor.attack.*
API (research item 2) and is UNEXECUTED — it has not been run against a
live pyrit install. Byte-compiles clean (py_compile) but that only proves
syntax validity, not that the pyrit API surface matches at runtime; treat
every claim below about pyrit's own behavior as sourced from the research
brief's direct reads of pyrit's source, not from having run it.

Target class used: HTTPXAPITarget (the research's PREFERRED option, not the
fallback). The research flagged one open item: whether json_data supports an
explicit prompt-substitution placeholder the way HTTPTarget's
prompt_regex_string does, or whether PyRIT substitutes the prompt into
json_data by field-name convention instead. That was not resolved by this
implementation either (no live pyrit install to smoke-test against) — see
the two-branch fallback below and the report's "hit a wall" note.
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
    """Preferred target class per the research. NOTE (unconfirmed, flagged
    in the research's "What could NOT be confirmed" section): the exact
    mechanism by which PyRIT substitutes the current attack prompt into a
    static `json_data: dict` was not read past the HTTPXAPITarget
    constructor signature in the research pass, and could not be resolved
    here either without a live install to smoke-test against. Two
    plausible mechanisms exist in PyRIT's own ecosystem conventions:
      (a) a placeholder token in a json_data string value, analogous to
          garak's "$INPUT" or HTTPTarget's "{PROMPT}" — attempted below.
      (b) PyRIT's PromptSendingAttack passing the prompt as a positional/
          keyword argument to _send_prompt_to_target_async independently
          of json_data, with json_data only supplying additional static
          fields.
    If (a) is wrong and HTTPXAPITarget raises or silently ignores the
    placeholder at runtime, fall back to build_http_target() below, which
    uses the CONFIRMED-working prompt_regex_string substitution mechanism.
    """
    from pyrit.prompt_target.http_target.httpx_api_target import HTTPXAPITarget

    return HTTPXAPITarget(
        http_url=SHIM_CHAT_URL,
        method="POST",
        headers={"Content-Type": "application/json"},
        json_data={"message": "{PROMPT}"},  # placeholder mechanism UNCONFIRMED — see docstring
        callback_function=parse_reply,
        max_requests_per_minute=MAX_REQUESTS_PER_MINUTE,
    )


def build_http_target():
    """Documented fallback (research item 2): HTTPTarget takes a raw HTTP
    request string plus a CONFIRMED regex substitution point
    (prompt_regex_string, default "{PROMPT}"). Use this if
    build_httpx_api_target()'s placeholder assumption turns out to be wrong
    against a live pyrit install.
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
        target = build_httpx_api_target()
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
        target = build_httpx_api_target()
    return CrescendoAttack(
        objective_target=target,
        adversarial_chat=adversarial_chat,
        scoring_target=scoring_target,
    )
