// PLANTED FLAW: an HTTP request parameter flows directly into a shell
// command executed with execSync. Classic command injection, reached via
// the same kind of untrusted-input path an LLM tool call would also use.
//
// Expected: 1 finding (http-request-to-shell-execution).

import { execSync } from "node:child_process";
import type { Request } from "express";

function pingHost(req: Request): string {
  const targetHost = req.body;
  return execSync(`ping -c 1 ${targetHost}`).toString();
}

export { pingHost };
