// Paired limit-experiment fixture (1 of 2): direct-call.ts
//
// This is the case the analyzer's cross-function propagation IS built to
// catch: a tainted value is passed directly, as a call argument, to a
// function whose body constructs a sink from that exact parameter. The
// callee is statically resolvable (one function declaration, no dynamic
// dispatch), so the analyzer can walk from the call site's argument into
// the function's parameter and body, matching the "Achievable in v1" case
// documented in README.md.
//
// Expected result: 1 finding.

import { SystemMessage } from "@langchain/core/messages";
import type { Request } from "express";

function processAndSend(value: string): void {
  const message = new SystemMessage(value);
  console.log(message);
}

function handleRequest(req: Request): void {
  const tainted = req.body;
  processAndSend(tainted);
}

export { handleRequest };
