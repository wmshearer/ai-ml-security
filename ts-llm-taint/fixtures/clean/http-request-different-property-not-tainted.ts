// CLEAN adversarial near-miss (must NOT be flagged): this specifically
// probes for over-broad object tainting. `req.body` is read into an
// object's `.debugInfo` property; only `.message` is ever passed to
// SystemMessage, and it is a hardcoded string. A detector that taints the
// whole containing object once ANY property is set from a source, rather
// than tracking the specific qualified property name, would misfire here
// by flagging `.message`.
//
// Expected: 0 findings.

import { SystemMessage } from "@langchain/core/messages";
import type { Request } from "express";

function buildDebugMessage(req: Request): SystemMessage {
  const payload = { debugInfo: req.body, message: "Static system prompt." };
  console.log(payload.debugInfo);
  return new SystemMessage(payload.message);
}

export { buildDebugMessage };
