// CLEAN adversarial near-miss (must NOT be flagged): a user-role message's
// content is read, but it never reaches ChatPromptTemplate.fromMessages --
// it only gets logged. A detector that just flags "a user-message object
// exists near a fromMessages call" without actually tracing the value would
// misfire here.
//
// Expected: 0 findings.

import { ChatPromptTemplate } from "@langchain/core/prompts";

interface IncomingMessage {
  role: string;
  content: string;
}

function buildPrompt(incoming: IncomingMessage): ChatPromptTemplate {
  const userTurn = { role: "user", content: incoming.content };
  console.log("received:", userTurn.content);
  return ChatPromptTemplate.fromMessages([
    ["system", "You are a helpful assistant."],
    ["user", "Please respond to the customer."],
  ]);
}

export { buildPrompt };
