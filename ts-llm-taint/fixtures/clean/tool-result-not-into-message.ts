// CLEAN adversarial near-miss (must NOT be flagged): the tool's `execute`
// callback returns a value, but it's a static status string, not anything
// derived from the tool's actual (potentially untrusted) work.
//
// Expected: 0 findings.

import { tool } from "ai";
import { z } from "zod";

const statusTool = tool({
  description: "Reports a fixed status message.",
  inputSchema: z.object({}),
  execute: async () => {
    return "ok";
  },
});

export { statusTool };
