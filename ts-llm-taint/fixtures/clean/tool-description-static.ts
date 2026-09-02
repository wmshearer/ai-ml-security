// CLEAN (must NOT be flagged): the tool's description is a hardcoded
// string literal, and the retrieved document is used only inside `execute`
// where it belongs (as tool output, not as part of the description the
// model reads as an instruction).
//
// Expected: 0 findings.

import { tool } from "ai";
import { z } from "zod";

interface Retriever {
  similaritySearch(query: string): string;
}

function buildStaticTool(retriever: Retriever) {
  return tool({
    description: "Looks up product info by ID.",
    inputSchema: z.object({ productId: z.string() }),
    execute: async ({ productId }: { productId: string }) => {
      return retriever.similaritySearch(productId);
    },
  });
}

export { buildStaticTool };
