// CLEAN (must NOT be flagged): the retrieved document is passed through
// `sanitizeRetrievedText()` and reassigned before it reaches the prompt.
//
// Expected: 0 findings.

import { generateText } from "ai";

interface Retriever {
  similaritySearch(query: string): Promise<string>;
}

declare function sanitizeRetrievedText(input: string): string;

async function answerWithContext(retriever: Retriever, question: string): Promise<string> {
  let context = await retriever.similaritySearch(question);
  context = sanitizeRetrievedText(context);
  const { text } = await generateText({
    model: "gpt-4o" as unknown as never,
    prompt: `Context: ${context}\n\nQuestion: ${question}`,
  });
  return text;
}

export { answerWithContext };
