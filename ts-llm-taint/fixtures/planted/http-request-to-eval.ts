// PLANTED FLAW: a value from an HTTP request query string flows directly
// into eval(). Arbitrary code execution.
//
// Expected: 1 finding (http-request-to-code-execution).

import type { Request } from "express";

function runExpression(req: Request): unknown {
  const expression = req.query;
  return eval(expression as unknown as string);
}

export { runExpression };
