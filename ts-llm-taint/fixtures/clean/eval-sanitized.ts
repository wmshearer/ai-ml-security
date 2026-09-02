// CLEAN (must NOT be flagged): the query value is sanitized and reassigned
// before reaching eval().
//
// Expected: 0 findings.

import type { Request } from "express";

declare function sanitize(input: unknown): string;

function runExpression(req: Request): unknown {
  let expression = req.query;
  expression = sanitize(expression) as unknown as typeof expression;
  return eval(expression as unknown as string);
}

export { runExpression };
