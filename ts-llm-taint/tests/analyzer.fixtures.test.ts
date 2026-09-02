/**
 * Runs the full analyzer against every fixture file and asserts the
 * expected finding count declared in each fixture's own header comment.
 * This mirrors the sibling Semgrep project's "one test file per rule with
 * both must-fire and must-not-fire cases" structure, but against real
 * ts-morph-parsed TypeScript files rather than YAML test cases.
 */

import { describe, expect, it } from "vitest";
import { Project } from "ts-morph";
import { analyzeSourceFile } from "../src/analyzer.js";

function analyzeFixture(relativePath: string) {
  const project = new Project({ skipAddingFilesFromTsConfig: true });
  project.addSourceFilesAtPaths(relativePath);
  const sourceFile = project.getSourceFiles()[0];
  if (sourceFile === undefined) {
    throw new Error(`Fixture not found: ${relativePath}`);
  }
  return analyzeSourceFile(sourceFile);
}

describe("planted-flaw fixtures (must produce at least 1 finding each)", () => {
  const plantedFixtures: ReadonlyArray<{ file: string; expectedRuleId: string }> = [
    { file: "fixtures/planted/http-request-to-system-message.ts", expectedRuleId: "http-request-to-prompt-construction" },
    { file: "fixtures/planted/user-message-to-chat-prompt-template.ts", expectedRuleId: "user-message-to-prompt-construction" },
    { file: "fixtures/planted/retrieved-document-to-generate-text.ts", expectedRuleId: "retrieved-document-to-prompt-construction" },
    { file: "fixtures/planted/retrieved-document-to-tool-description.ts", expectedRuleId: "retrieved-document-to-prompt-construction" },
    { file: "fixtures/planted/retrieved-document-to-system-message-in-tool.ts", expectedRuleId: "retrieved-document-to-prompt-construction" },
    { file: "fixtures/planted/http-request-to-shell-execution.ts", expectedRuleId: "http-request-to-shell-execution" },
    { file: "fixtures/planted/http-request-to-eval.ts", expectedRuleId: "http-request-to-code-execution" },
    { file: "fixtures/planted/http-request-to-sql-query.ts", expectedRuleId: "http-request-to-sql-query" },
    { file: "fixtures/planted/http-request-to-file-read.ts", expectedRuleId: "http-request-to-file-path" },
    { file: "fixtures/planted/http-request-to-dangerously-set-inner-html.ts", expectedRuleId: "http-request-to-unsanitized-render" },
  ];

  for (const { file, expectedRuleId } of plantedFixtures) {
    it(`flags ${file}`, () => {
      const findings = analyzeFixture(file);
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings.some((f) => f.ruleId === expectedRuleId)).toBe(true);
    });
  }

  it("flags human-message-into-fromMessages.ts with exactly 2 findings on the same root cause", () => {
    const findings = analyzeFixture("fixtures/planted/human-message-into-fromMessages.ts");
    expect(findings).toHaveLength(2);
    const ruleIds = findings.map((f) => f.ruleId).sort();
    expect(ruleIds).toEqual(["http-request-to-prompt-construction", "user-message-to-prompt-construction"]);
  });
});

describe("clean fixtures (must produce 0 findings)", () => {
  const cleanFixtures = [
    "fixtures/clean/http-request-to-system-message-sanitized.ts",
    "fixtures/clean/hardcoded-system-message.ts",
    "fixtures/clean/user-message-not-into-fromMessages.ts",
    "fixtures/clean/retrieved-document-sanitized.ts",
    "fixtures/clean/retrieved-document-not-into-prompt.ts",
    "fixtures/clean/retrieved-document-in-tool-not-into-message.ts",
    "fixtures/clean/tool-description-static.ts",
    "fixtures/clean/tool-result-sanitized.ts",
    "fixtures/clean/tool-result-not-into-message.ts",
    "fixtures/clean/shell-execution-sanitized.ts",
    "fixtures/clean/shell-execution-hardcoded.ts",
    "fixtures/clean/eval-hardcoded.ts",
    "fixtures/clean/eval-sanitized.ts",
    "fixtures/clean/sql-query-parameterized.ts",
    "fixtures/clean/sql-query-sanitized.ts",
    "fixtures/clean/file-read-sanitized.ts",
    "fixtures/clean/file-read-hardcoded.ts",
    "fixtures/clean/human-message-hardcoded.ts",
    "fixtures/clean/http-request-different-property-not-tainted.ts",
  ];

  for (const file of cleanFixtures) {
    it(`does not flag ${file}`, () => {
      const findings = analyzeFixture(file);
      expect(findings).toHaveLength(0);
    });
  }
});

describe("the paired limit experiment (callback indirection boundary)", () => {
  it("catches the direct-call case: exactly 1 finding", () => {
    const findings = analyzeFixture("fixtures/limit-experiment/direct-call.ts");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("http-request-to-prompt-construction");
  });

  it("does NOT catch the callback-indirection case: exactly 0 findings", () => {
    const findings = analyzeFixture("fixtures/limit-experiment/callback-indirection.ts");
    expect(findings).toHaveLength(0);
  });
});
