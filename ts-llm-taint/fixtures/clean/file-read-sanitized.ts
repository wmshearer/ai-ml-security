// CLEAN (must NOT be flagged): the request path is normalized/sanitized and
// reassigned before it reaches fs.readFile.
//
// Expected: 0 findings.

import * as fs from "node:fs";
import type { Request } from "express";

declare function normalizePath(input: unknown): string;

function readUserFile(req: Request): void {
  let requestedPath = req.query;
  requestedPath = normalizePath(requestedPath) as unknown as typeof requestedPath;
  fs.readFile(requestedPath as unknown as string, () => undefined);
}

export { readUserFile };
