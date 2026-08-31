// PLANTED FLAW: an AI SDK tool's execute() callback returns
// `new SystemMessage(...)` directly -- the model's next turn is built from
// exactly what the tool call returns, with no separation between "what the
// tool produced" and "what the model is told to trust." The
// `tool-result-return` source rule (sources.ts) marks this whole returned
// expression as untrusted tool-produced data; it is, at the same time, a
// recognized `SystemMessage` sink (sinks.ts). The analyzer's own dangerous-
// argument check still requires the ARGUMENT to `SystemMessage` (not the
// constructor call itself) to be tainted, so this fixture nests the
// argument as a call to a second recognized source (`retriever.
// similaritySearch`) to make the flow concrete and traceable end to end.
//
// Expected: 1 finding (retrieved-document-to-prompt-construction) -- see
// FINDINGS.md for why `tool-result-return` specifically could not be made
// to compose as the reported source in a realistic fixture; the source
// rule exists and is unit-tested directly (tests/sources.test.ts), but no
// natural single-file fixture was found where it is also the reported
// finding's source, because its own captured node is the entire `return`
// expression rather than a reusable identifier.

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
      return new SystemMessage(retriever.similaritySearch(query));
    },
  });
}

export { buildLookupTool };
