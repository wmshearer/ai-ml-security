// PLANTED FLAW: a user-role message's content flows into
// ChatPromptTemplate.fromMessages, and that same array is what actually gets
// sent to the model. This flow is intraprocedural and templated through a
// string interpolation, exercising the analyzer's template-literal
// propagation (see propagation.ts's `TemplateExpression` handling).
//
// Expected: 1 finding (user-message-to-prompt-construction).

import { ChatPromptTemplate } from "@langchain/core/prompts";

interface IncomingMessage {
  role: string;
  content: string;
}

function buildPrompt(incoming: IncomingMessage): ChatPromptTemplate {
  const userTurn = { role: "user", content: incoming.content };
  const rendered = `User said: ${userTurn.content}`;
  return ChatPromptTemplate.fromMessages([
    ["system", "You are a helpful assistant."],
    ["user", rendered],
  ]);
}

export { buildPrompt };
