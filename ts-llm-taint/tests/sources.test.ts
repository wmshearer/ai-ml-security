/**
 * Unit tests for individual source rules, isolated from the full analyzer
 * pipeline. Each test parses a small inline snippet with ts-morph and
 * checks whether the rule under test matches the expected node (or
 * correctly does not match, for the false-positive exclusions).
 */

import { describe, expect, it } from "vitest";
import { Project, SyntaxKind } from "ts-morph";
import { sourceRules } from "../src/sources.js";

function firstMatch(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  const sourceFile = project.createSourceFile("snippet.ts", code);
  let match: ReturnType<(typeof sourceRules)[number]["match"]> | undefined;
  sourceFile.forEachDescendant((node) => {
    if (match !== undefined) {
      return;
    }
    for (const rule of sourceRules) {
      const m = rule.match(node);
      if (m !== undefined) {
        match = m;
        return;
      }
    }
  });
  return match;
}

describe("http-request-property source rule", () => {
  it("matches req.body", () => {
    const match = firstMatch(`function f(req: any) { const x = req.body; }`);
    expect(match?.category).toBe("http-request");
  });

  it("matches req.query and req.params", () => {
    expect(firstMatch(`function f(req: any) { req.query; }`)?.category).toBe("http-request");
    expect(firstMatch(`function f(req: any) { req.params; }`)?.category).toBe("http-request");
  });

  it("does not match an unrelated property access", () => {
    const match = firstMatch(`function f(req: any) { req.headers; }`);
    expect(match).toBeUndefined();
  });
});

describe("human-message-constructor-arg source rule", () => {
  it("matches a non-literal argument", () => {
    const match = firstMatch(`
      class HumanMessage { constructor(content: string) {} }
      function f(x: string) { new HumanMessage(x); }
    `);
    expect(match?.category).toBe("user-message");
  });

  it("does NOT match a hardcoded string literal argument (false-positive exclusion)", () => {
    const match = firstMatch(`
      class HumanMessage { constructor(content: string) {} }
      new HumanMessage("hello");
    `);
    expect(match).toBeUndefined();
  });

  it("does NOT match a hardcoded template literal with no substitutions", () => {
    const match = firstMatch(`
      class HumanMessage { constructor(content: string) {} }
      new HumanMessage(\`hello\`);
    `);
    expect(match).toBeUndefined();
  });
});

describe("user-message-object source rule", () => {
  it("matches { role: 'user', content: <non-literal> }", () => {
    const match = firstMatch(`function f(x: string) { const m = { role: "user", content: x }; }`);
    expect(match?.category).toBe("user-message");
  });

  it("does not match a hardcoded content value", () => {
    const match = firstMatch(`const m = { role: "user", content: "hi" };`);
    expect(match).toBeUndefined();
  });

  it("does not match a non-user role", () => {
    const match = firstMatch(`function f(x: string) { const m = { role: "assistant", content: x }; }`);
    expect(match).toBeUndefined();
  });
});

describe("retriever-call-result source rule", () => {
  it("matches .similaritySearch(...)", () => {
    const match = firstMatch(`
      interface Retriever { similaritySearch(q: string): string; }
      function f(r: Retriever, q: string) { r.similaritySearch(q); }
    `);
    expect(match?.category).toBe("retrieved-document");
  });

  it("matches .invoke() on something named retriever", () => {
    const match = firstMatch(`
      interface Retriever { invoke(q: string): string; }
      function f(retriever: Retriever, q: string) { retriever.invoke(q); }
    `);
    expect(match?.category).toBe("retrieved-document");
  });

  it("does not match .invoke() on an unrelated object", () => {
    const match = firstMatch(`
      interface Thing { invoke(q: string): string; }
      function f(thing: Thing, q: string) { thing.invoke(q); }
    `);
    expect(match).toBeUndefined();
  });
});

describe("tool-result-return source rule", () => {
  it("matches a return statement inside a tool()'s execute callback", () => {
    const code = `
      declare function tool(config: unknown): unknown;
      declare function callApi(q: string): string;
      tool({
        description: "x",
        execute: async (q: string) => {
          return callApi(q);
        },
      });
    `;
    const project = new Project({ useInMemoryFileSystem: true });
    const sourceFile = project.createSourceFile("snippet.ts", code);
    let found = false;
    sourceFile.forEachDescendant((node) => {
      if (!node.isKind(SyntaxKind.ReturnStatement)) {
        return;
      }
      for (const rule of sourceRules) {
        if (rule.id === "tool-result-return" && rule.match(node) !== undefined) {
          found = true;
        }
      }
    });
    expect(found).toBe(true);
  });

  it("does not match a return statement outside a tool definition", () => {
    const code = `
      function plain(q: string) {
        return q;
      }
    `;
    const project = new Project({ useInMemoryFileSystem: true });
    const sourceFile = project.createSourceFile("snippet.ts", code);
    let found = false;
    sourceFile.forEachDescendant((node) => {
      if (!node.isKind(SyntaxKind.ReturnStatement)) {
        return;
      }
      for (const rule of sourceRules) {
        if (rule.id === "tool-result-return" && rule.match(node) !== undefined) {
          found = true;
        }
      }
    });
    expect(found).toBe(false);
  });
});
