// CLEAN adversarial near-miss (must NOT be flagged): execSync is called
// with a fully hardcoded command string. No source at all.
//
// Expected: 0 findings.

import { execSync } from "node:child_process";

function checkUptime(): string {
  return execSync("uptime").toString();
}

export { checkUptime };
