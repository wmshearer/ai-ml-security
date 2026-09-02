// CLEAN adversarial near-miss (must NOT be flagged): the tool's execute()
// callback retrieves a document but returns a fixed, hardcoded status
// value, never the retrieved content itself.
//
// Expected: 0 findings.

import { tool } from "ai";
import { SystemMessage } from "@langchain/core/messages";
import { z } from "zod";

interface Retriever {
  similaritySearch(query: string): string;
}

function buildLookupTool(retriever: Retriever) {
  return tool({
    description: "Looks up a record from the vector store.",
    inputSchema: z.object({ query: z.string() }),
    execute: async ({ query }: { query: string }) => {
      const record = retriever.similaritySearch(query);
      console.log("audit log:", record);
      return new SystemMessage("Lookup complete.");
    },
  });
}

export { buildLookupTool };
