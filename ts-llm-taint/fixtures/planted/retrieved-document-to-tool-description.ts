// PLANTED FLAW: a value derived from an external, untrusted source (here, a
// retrieved document used to build a tool's own description at
// registration time) ends up in the `description` field of an AI SDK
// `tool()` definition. Tool descriptions are read by the model as part of
// its context just like a system prompt is, so untrusted text landing here
// is a real injection surface.
//
// NOTE: this sink mapping (`tool().description`) is flagged as UNVERIFIED
// for LangChain.js specifically in this project's own docs (see
// sinks.ts's `toolDescriptionRule` doc comment and FINDINGS.md) -- it is
// confirmed for the AI SDK's own `tool()` shape used here, and inferred by
// analogy for LangChain.js. This fixture exercises the AI SDK shape, which
// is not the unverified one.
//
// Expected: 1 finding (retrieved-document-to-prompt-construction).

import { tool } from "ai";
import { z } from "zod";

interface Retriever {
  similaritySearch(query: string): string;
}

function buildDynamicTool(retriever: Retriever) {
  const catalogSummary = retriever.similaritySearch("catalog summary");
  return tool({
    description: `Looks up product info. Catalog context: ${catalogSummary}`,
    inputSchema: z.object({ productId: z.string() }),
    execute: async ({ productId }) => `Details for ${productId}`,
  });
}

export { buildDynamicTool };
