// PLANTED FLAW: an HTTP request parameter is joined into a file path and
// passed unsanitized to fs.readFile. Path traversal risk.
//
// Expected: 1 finding (http-request-to-file-path).

import * as fs from "node:fs";
import type { Request } from "express";

function readUserFile(req: Request): void {
  const requestedPath = req.query;
  fs.readFile(requestedPath as unknown as string, () => undefined);
}

export { readUserFile };
