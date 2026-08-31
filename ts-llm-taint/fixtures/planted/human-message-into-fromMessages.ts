// PLANTED FLAW: a HumanMessage is built directly from an HTTP request
// value with no sanitizer, and that message is included in the array
// passed to ChatPromptTemplate.fromMessages.
//
// Expected: 2 findings on the same root cause, from two different rule
// pairs: (1) http-request-to-prompt-construction, the request value
// reaching the HumanMessage constructor argument, and (2)
// user-message-to-prompt-construction, because the HumanMessage
// constructor argument is itself also recognized as a user-message source
// (a HumanMessage's content is, definitionally, user-controlled), which
// then re-matches the same HumanMessage constructor as a sink. Both
// findings point at the same line and the same real bug; this is not
// double-counting a false positive, it is two independent, correct rule
// pairs agreeing on one vulnerable line.

import { ChatPromptTemplate } from "@langchain/core/prompts";
import { HumanMessage } from "@langchain/core/messages";
import type { Request } from "express";

function buildPrompt(req: Request): ChatPromptTemplate {
  const userInput = req.body;
  return ChatPromptTemplate.fromMessages([
    ["system", "You are a helpful assistant."],
    new HumanMessage(userInput),
  ]);
}

export { buildPrompt };
