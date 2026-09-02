// CLEAN (must NOT be flagged): the request body is sanitized and
// reassigned before it reaches the shell command.
//
// Expected: 0 findings.

import { execSync } from "node:child_process";
import type { Request } from "express";

declare function sanitize(input: unknown): string;

function pingHost(req: Request): string {
  let targetHost = req.body;
  targetHost = sanitize(targetHost);
  return execSync(`ping -c 1 ${targetHost}`).toString();
}

export { pingHost };
