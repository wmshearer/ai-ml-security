/**
 * Unit tests for the propagation engine (`isExpressionTainted`,
 * `propagateThroughStatements`, and the sanitizer-reassignment idiom),
 * independent of the sources/sinks rule tables.
 */

import { describe, expect, it } from "vitest";
import { Project, SyntaxKind, type Block, type Identifier } from "ts-morph";
import { TaintState, isExpressionTainted, propagateThroughStatements, defaultSanitizers } from "../src/propagation.js";

function setupBlock(code: string): Block {
  const project = new Project({ useInMemoryFileSystem: true });
  const sourceFile = project.createSourceFile("snippet.ts", `function __wrapper() {\n${code}\n}`);
  const fn = sourceFile.getFunctions()[0];
  if (fn === undefined) {
    throw new Error("expected a function");
  }
  return fn.getBodyOrThrow() as Block;
}

/**
 * Returns the `occurrence`-th (0-indexed) `Identifier` node with the given
 * text in `block`, in source order. Used to pick out a specific *reference*
 * to a variable (e.g. its first use, as opposed to its declaration) as the
 * taint origin passed to `isExpressionTainted`/`propagateThroughStatements`,
 * both of which key off exact AST node identity rather than symbol
 * equality for the initial "is this the source" check.
 */
function nthIdentifier(block: Block, name: string, occurrence: number): Identifier {
  const matches = block.getDescendantsOfKind(SyntaxKind.Identifier).filter((i) => i.getText() === name);
  const found = matches[occurrence];
  if (found === undefined) {
    throw new Error(`expected occurrence ${occurrence} of identifier "${name}", found ${matches.length}`);
  }
  return found;
}

describe("direct assignment propagation", () => {
  it("propagates taint through const b = a;", () => {
    const body = setupBlock(`
      declare const source: string;
      const a = source;
      const b = a;
    `);
    // occurrence 0 is the `declare const source` binding itself; occurrence
    // 1 is its use in `const a = source;`, which is the taint origin.
    const sourceNode = nthIdentifier(body, "source", 1);

    const state = new TaintState();
    propagateThroughStatements(body, state, sourceNode, defaultSanitizers);

    const bDecl = body.getDescendantsOfKind(SyntaxKind.VariableDeclaration).find((d) => d.getName() === "b");
    const bIdentifier = bDecl!.getNameNode();
    expect(bIdentifier.isKind(SyntaxKind.Identifier)).toBe(true);
    expect(state.isIdentifierTainted(bIdentifier as Identifier)).toBe(true);
  });
});

describe("template literal propagation", () => {
  it("marks a template expression tainted if any interpolation is tainted", () => {
    const body = setupBlock(`
      declare const source: string;
      const rendered = \`prefix-\${source}-suffix\`;
    `);
    const sourceNode = nthIdentifier(body, "source", 1);
    const templateExpr = body.getDescendantsOfKind(SyntaxKind.TemplateExpression)[0];
    expect(templateExpr).toBeDefined();

    const state = new TaintState();
    expect(isExpressionTainted(templateExpr!, state, sourceNode, defaultSanitizers)).toBe(true);
  });
});

describe("sanitizer reassignment idiom", () => {
  it("clears taint when the tainted variable is reassigned through a sanitizer call", () => {
    const body = setupBlock(`
      declare const source: string;
      declare function sanitize(x: string): string;
      let value = source;
      value = sanitize(value);
    `);
    const sourceNode = nthIdentifier(body, "source", 1);
    const state = new TaintState();
    propagateThroughStatements(body, state, sourceNode, defaultSanitizers);

    const valueIdentifiers = body.getDescendantsOfKind(SyntaxKind.Identifier).filter((i) => i.getText() === "value");
    const lastValueRef = valueIdentifiers[valueIdentifiers.length - 1];
    expect(state.isIdentifierTainted(lastValueRef!)).toBe(false);
  });

  it("does NOT clear taint from a bare gating call that does not reassign the variable", () => {
    // Mirrors the documented Semgrep-project finding: a plain
    // `if (!authorize(x)) return;` does not sanitize `x`, because it never
    // reassigns it. This analyzer requires the reassignment idiom too.
    const body = setupBlock(`
      declare const source: string;
      declare function authorize(x: string): boolean;
      const value = source;
      if (authorize(value)) {
        console.log(value);
      }
    `);
    const sourceNode = nthIdentifier(body, "source", 1);
    const state = new TaintState();
    propagateThroughStatements(body, state, sourceNode, defaultSanitizers);

    const valueIdentifiers = body.getDescendantsOfKind(SyntaxKind.Identifier).filter((i) => i.getText() === "value");
    const consoleLogArg = valueIdentifiers[valueIdentifiers.length - 1];
    expect(state.isIdentifierTainted(consoleLogArg!)).toBe(true);
  });
});

describe("direct function-call argument-to-parameter propagation", () => {
  it("follows taint into a single statically resolvable callee and back out through its return", () => {
    const body = setupBlock(`
      declare const source: string;
      function wrap(v: string): string {
        return v;
      }
      const result = wrap(source);
    `);
    const sourceNode = nthIdentifier(body, "source", 1);
    const call = body.getDescendantsOfKind(SyntaxKind.CallExpression)[0];
    expect(call).toBeDefined();

    const state = new TaintState();
    expect(isExpressionTainted(call!, state, sourceNode, defaultSanitizers)).toBe(true);
  });

  it("does not propagate through a call whose callee cannot be uniquely resolved (overload-shaped ambiguity)", () => {
    const body = setupBlock(`
      declare const source: string;
      declare function ambiguous(v: string): string;
      const result = ambiguous(source);
    `);
    const sourceNode = nthIdentifier(body, "source", 1);
    const call = body.getDescendantsOfKind(SyntaxKind.CallExpression)[0];

    const state = new TaintState();
    // `ambiguous` is an ambient declaration with no body ts-morph can walk
    // into, so propagation through it must not silently claim to trace it.
    expect(isExpressionTainted(call!, state, sourceNode, defaultSanitizers)).toBe(false);
  });
});

describe("object property assignment / object-literal propagation", () => {
  it("marks obj.field tainted from an object literal, and does not taint an unrelated field", () => {
    const body = setupBlock(`
      declare const source: string;
      const obj = { tainted: source, clean: "literal" };
    `);
    const sourceNode = nthIdentifier(body, "source", 1);
    const state = new TaintState();
    propagateThroughStatements(body, state, sourceNode, defaultSanitizers);

    expect(state.isQualifiedNameTainted("obj.tainted")).toBe(true);
    expect(state.isQualifiedNameTainted("obj.clean")).toBe(false);
  });
});
