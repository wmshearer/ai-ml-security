// Paired limit-experiment fixture (2 of 2): callback-indirection.ts
//
// Minimally different from direct-call.ts in this same directory: the sink
// still lives inside a function body, and the tainted value still
// originates from the same source (`req.body`), but the connection between
// them is made through a callback registered into a module-level array and
// invoked later by unrelated code via a runtime lookup (by index), not
// through a direct call argument.
//
// No static edge connects "value passed to dispatch()" to "value received
// as the callback's parameter" -- that binding exists only once the program
// actually runs and `handlers[0]` happens to be the callback that was
// pushed earlier. A syntax-tree walk has no way to know, at analysis time,
// which callback occupies which array slot, or that dispatch's argument is
// the same value the stored callback will eventually receive.
//
// Expected result: 0 findings. This is the boundary this project measures
// and reports honestly as a hard wall for this specific hand-built
// ts-morph pass (see FINDINGS.md), not a claim about static analysis in
// general.

import { SystemMessage } from "@langchain/core/messages";
import type { Request } from "express";

type Handler = (value: string) => void;

const handlers: Handler[] = [];

function registerHandler(handler: Handler): void {
  handlers.push(handler);
}

function dispatch(value: string): void {
  const handler = handlers[0];
  if (handler !== undefined) {
    handler(value);
  }
}

registerHandler((value: string) => {
  const message = new SystemMessage(value);
  console.log(message);
});

function handleRequest(req: Request): void {
  const tainted = req.body;
  dispatch(tainted);
}

export { handleRequest };
