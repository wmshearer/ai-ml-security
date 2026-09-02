// CLEAN (must NOT be flagged): the request body is passed through
// `sanitize()` and reassigned before it reaches SystemMessage. The analyzer
// recognizes a sanitizer only when it reassigns the tainted variable (the
// `x = sanitize(x)` idiom) -- see propagation.ts and README.md "Scope".
//
// Expected: 0 findings.

import { SystemMessage } from "@langchain/core/messages";
import type { Request } from "express";

declare function sanitize(input: unknown): string;

function handleRequest(req: Request): SystemMessage {
  let userInstruction = req.body;
  userInstruction = sanitize(userInstruction);
  return new SystemMessage(userInstruction);
}

export { handleRequest };
