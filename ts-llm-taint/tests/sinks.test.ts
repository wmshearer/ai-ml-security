/**
 * Unit tests for individual sink rules, isolated from the full analyzer
 * pipeline.
 */

import { describe, expect, it } from "vitest";
import { Project } from "ts-morph";
import { sinkRules } from "../src/sinks.js";

function firstMatch(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  const sourceFile = project.createSourceFile("snippet.ts", code);
  let match: ReturnType<(typeof sinkRules)[number]["match"]> | undefined;
  sourceFile.forEachDescendant((node) => {
    if (match !== undefined) {
      return;
    }
    for (const rule of sinkRules) {
      const m = rule.match(node);
      if (m !== undefined) {
        match = m;
        return;
      }
    }
  });
  return match;
}

describe("chat-message-constructor sink rule", () => {
  it("matches new SystemMessage(...)", () => {
    const match = firstMatch(`
      class SystemMessage { constructor(c: string) {} }
      new SystemMessage("x");
    `);
    expect(match?.category).toBe("prompt-construction");
    expect(match?.dangerousArguments).toHaveLength(1);
  });

  it("matches new HumanMessage(...)", () => {
    const match = firstMatch(`
      class HumanMessage { constructor(c: string) {} }
      new HumanMessage("x");
    `);
    expect(match?.category).toBe("prompt-construction");
  });

  it("does not match an unrelated constructor", () => {
    const match = firstMatch(`
      class SomethingElse { constructor(c: string) {} }
      new SomethingElse("x");
    `);
    expect(match).toBeUndefined();
  });
});

describe("chat-prompt-template-from-messages sink rule", () => {
  it("matches ChatPromptTemplate.fromMessages([...])", () => {
    const match = firstMatch(`
      declare const ChatPromptTemplate: { fromMessages(m: unknown[]): unknown };
      ChatPromptTemplate.fromMessages([["system", "x"]]);
    `);
    expect(match?.category).toBe("prompt-construction");
  });
});

describe("ai-sdk-generate-call sink rule", () => {
  it("matches generateText({ system, prompt, messages })", () => {
    const code = `
      declare function generateText(opts: { system?: string; prompt?: string; messages?: unknown[] }): unknown;
      generateText({ system: "s", prompt: "p", messages: [] });
    `;
    const match = firstMatch(code);
    expect(match?.category).toBe("prompt-construction");
    expect(match?.dangerousArguments.length).toBeGreaterThanOrEqual(2);
  });

  it("matches streamText with only a prompt field", () => {
    const code = `
      declare function streamText(opts: { prompt?: string }): unknown;
      streamText({ prompt: "p" });
    `;
    const match = firstMatch(code);
    expect(match?.category).toBe("prompt-construction");
    expect(match?.dangerousArguments).toHaveLength(1);
  });

  it("does not match a call to an unrelated function with the same option shape", () => {
    const code = `
      declare function notGenerateText(opts: { prompt?: string }): unknown;
      notGenerateText({ prompt: "p" });
    `;
    expect(firstMatch(code)).toBeUndefined();
  });
});

describe("tool-description-field sink rule", () => {
  it("matches description inside a tool(...) call", () => {
    const code = `
      declare function tool(config: { description: string }): unknown;
      declare const dynamicDescription: string;
      tool({ description: dynamicDescription });
    `;
    const match = firstMatch(code);
    expect(match?.category).toBe("prompt-construction");
    expect(match?.description).toContain("UNVERIFIED");
  });

  it("does not match a description field outside a tool() call", () => {
    const code = `declare const obj: { description: string }; const x = { description: "y" };`;
    expect(firstMatch(code)).toBeUndefined();
  });
});

describe("code-execution sink rule", () => {
  it("matches eval(...)", () => {
    const match = firstMatch(`declare const expr: string; eval(expr);`);
    expect(match?.category).toBe("code-execution");
  });

  it("matches new Function(...)", () => {
    const match = firstMatch(`declare const body: string; new Function(body);`);
    expect(match?.category).toBe("code-execution");
  });
});

describe("shell-execution sink rule", () => {
  it("matches a directly imported execSync(...)", () => {
    const code = `
      declare function execSync(cmd: string): Buffer;
      declare const cmd: string;
      execSync(cmd);
    `;
    const match = firstMatch(code);
    expect(match?.category).toBe("shell-execution");
  });

  it("matches child_process.execSync(...)", () => {
    const code = `
      declare const child_process: { execSync(cmd: string): Buffer };
      declare const cmd: string;
      child_process.execSync(cmd);
    `;
    const match = firstMatch(code);
    expect(match?.category).toBe("shell-execution");
  });
});

describe("sql-query sink rule", () => {
  it("matches db.query(...)", () => {
    const code = `
      declare const db: { query(sql: string): unknown };
      declare const sql: string;
      db.query(sql);
    `;
    const match = firstMatch(code);
    expect(match?.category).toBe("sql-query");
  });
});

describe("file-path sink rule", () => {
  it("matches fs.readFile(...)", () => {
    const code = `
      declare const fs: { readFile(path: string, cb: () => void): void };
      declare const path: string;
      fs.readFile(path, () => undefined);
    `;
    const match = firstMatch(code);
    expect(match?.category).toBe("file-path");
  });

  it("does not match readFile on an unrelated object", () => {
    const code = `
      declare const notFs: { readFile(path: string, cb: () => void): void };
      declare const path: string;
      notFs.readFile(path, () => undefined);
    `;
    expect(firstMatch(code)).toBeUndefined();
  });
});

describe("dangerously-set-inner-html sink rule", () => {
  it("matches __html inside dangerouslySetInnerHTML", () => {
    const code = `declare const rawHtml: string; const props = { dangerouslySetInnerHTML: { __html: rawHtml } };`;
    const match = firstMatch(code);
    expect(match?.category).toBe("unsanitized-render");
  });
});
