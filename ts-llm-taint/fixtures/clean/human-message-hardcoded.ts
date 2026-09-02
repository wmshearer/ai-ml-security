// CLEAN adversarial near-miss (must NOT be flagged): HumanMessage and the
// prompt template are built entirely from hardcoded string literals. No
// source at all.
//
// Expected: 0 findings.

import { ChatPromptTemplate } from "@langchain/core/prompts";
import { HumanMessage } from "@langchain/core/messages";

function buildPrompt(): ChatPromptTemplate {
  return ChatPromptTemplate.fromMessages([
    ["system", "You are a helpful assistant."],
    new HumanMessage("Hello, how can I help you today?"),
  ]);
}

export { buildPrompt };
