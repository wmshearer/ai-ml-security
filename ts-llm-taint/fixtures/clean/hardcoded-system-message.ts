// CLEAN (must NOT be flagged): SystemMessage built entirely from a hardcoded
// string literal. There is no source at all -- an over-broad detector that
// flags every SystemMessage construction, rather than tracing an actual
// tainted value into it, would misfire here.
//
// Expected: 0 findings.

import { SystemMessage } from "@langchain/core/messages";

function buildSystemMessage(): SystemMessage {
  return new SystemMessage("You are a helpful assistant. Answer concisely.");
}

export { buildSystemMessage };
