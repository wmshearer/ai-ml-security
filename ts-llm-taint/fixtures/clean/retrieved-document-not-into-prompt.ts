// CLEAN adversarial near-miss (must NOT be flagged): a document is
// retrieved and logged, but the actual prompt sent to generateText is a
// fixed string built only from the (trusted) question, never the retrieved
// content.
//
// Expected: 0 findings.

import { generateText } from "ai";

interface Retriever {
  similaritySearch(query: string): Promise<string>;
}

async function answerWithContext(retriever: Retriever, question: string): Promise<string> {
  const context = await retriever.similaritySearch(question);
  console.log("retrieved for audit log:", context);
  const { text } = await generateText({
    model: "gpt-4o" as unknown as never,
    prompt: `Question: ${question}`,
  });
  return text;
}

export { answerWithContext };
