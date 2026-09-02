// CLEAN (must NOT be flagged): the tool's raw result is passed through
// `sanitize()` and reassigned before it becomes a ToolMessage.
//
// Expected: 0 findings.

import { ToolMessage } from "@langchain/core/messages";

declare function callExternalApi(query: string): string;
declare function sanitize(input: string): string;

function runToolAndRespond(query: string): ToolMessage {
  let apiResult = callExternalApi(query);
  apiResult = sanitize(apiResult);
  return new ToolMessage(apiResult);
}

export { runToolAndRespond };
