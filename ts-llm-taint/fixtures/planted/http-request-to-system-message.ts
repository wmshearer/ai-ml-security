// PLANTED FLAW: an HTTP request body flows straight into a SystemMessage,
// with no sanitizer between them. The model will treat req.body as part of
// its trusted system prompt.
//
// Expected: 1 finding (http-request-to-prompt-construction).

import { SystemMessage } from "@langchain/core/messages";
import type { Request } from "express";

function handleRequest(req: Request): SystemMessage {
  const userInstruction = req.body;
  return new SystemMessage(userInstruction);
}

export { handleRequest };
