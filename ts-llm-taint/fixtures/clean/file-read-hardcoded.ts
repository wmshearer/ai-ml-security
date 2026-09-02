// CLEAN adversarial near-miss (must NOT be flagged): fs.readFile is called
// with a hardcoded, fixed path -- no source at all.
//
// Expected: 0 findings.

import * as fs from "node:fs";

function readConfig(): void {
  fs.readFile("./config.json", () => undefined);
}

export { readConfig };
