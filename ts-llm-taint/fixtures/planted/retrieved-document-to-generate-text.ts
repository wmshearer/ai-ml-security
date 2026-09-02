// PLANTED FLAW: a document pulled back by a retriever (RAG: retrieval-
// augmented generation) is concatenated directly into the `prompt` sent to
// the Vercel AI SDK's generateText, with no separation between "trusted
// instruction" and "untrusted reference text." If the retrieved document
// contains something that reads like an instruction, the model has no
// structural way to tell it apart from the real prompt.
//
// The retriever call itself is awaited but its result is assigned directly
// (no destructuring) -- direct assignment from an awaited expression is
// within the analyzer's documented propagation scope; destructuring
// assignment is not (see README "Scope").
//
// Expected: 1 finding (retrieved-document-to-prompt-construction).

import { generateText } from "ai";

interface Retriever {
  similaritySearch(query: string): Promise<string>;
}

async function answerWithContext(retriever: Retriever, question: string): Promise<string> {
  const context = await retriever.similaritySearch(question);
  const { text } = await generateText({
    model: "gpt-4o" as unknown as never,
    prompt: `Context: ${context}\n\nQuestion: ${question}`,
  });
  return text;
}

export { answerWithContext };
