/**
 * Taint propagation.
 *
 * Neither ts-morph nor the raw TypeScript compiler API gives you a
 * control-flow graph or a dataflow graph for free — both only expose the
 * syntax tree (the AST: the parsed, structured representation of the code)
 * and a type checker. Tracing "can a tainted value reach this sink" has to
 * be written here, statement by statement.
 *
 * What this engine tracks, deliberately scoped (see README/FINDINGS for the
 * full boundary list):
 *   - direct assignment (`const b = a;`)
 *   - template literals (`` `...${a}...` ``)
 *   - object property assignment (`obj.field = a`), tracked per qualified name
 *   - a direct function call where the callee resolves to exactly one
 *     statically known function/arrow declaration (no overloads, no dynamic
 *     dispatch) — taint is carried from argument to parameter and the walk
 *     continues into the callee's body
 *   - return-value propagation from a called function back to the call site
 *   - a sanitizer, recognized only as a call that *reassigns* the tainted
 *     variable (`x = sanitize(x)`), matching the same idiom the sibling
 *     Semgrep project required
 *
 * What it does NOT track (see README "Scope" section for the full list):
 * dynamic property access, callback/higher-order indirection, control-flow
 * sensitive branching, async/Promise boundaries, cross-module barrel
 * re-exports beyond ts-morph's own `findReferences()`.
 */

import type { Node, Identifier, SourceFile } from "ts-morph";
import { SyntaxKind } from "ts-morph";

/** Names of functions that, when called on a tainted value, clear the taint. */
export interface SanitizerConfig {
  readonly functionNames: readonly string[];
}

export const defaultSanitizers: SanitizerConfig = {
  functionNames: ["sanitize", "sanitizeInput", "escapeHtml", "sanitizeRetrievedText", "normalizePath"],
};

/** One hop in a taint trace, kept for reporting a human-readable path. */
export interface TaintStep {
  readonly node: Node;
  readonly description: string;
}

/**
 * Tracks which identifiers (by symbol) and which qualified property names
 * (e.g. `obj.field`) are currently considered tainted within one traversal.
 * A fresh `TaintState` is used per top-level source expression being traced,
 * so state does not leak between unrelated traces.
 */
class TaintState {
  private readonly taintedSymbolIds = new Set<number>();
  private readonly taintedQualifiedNames = new Set<string>();
  private readonly visitedFunctions = new Set<number>();

  markIdentifierTainted(identifier: Identifier): void {
    const symbol = identifier.getSymbol();
    if (symbol !== undefined) {
      this.taintedSymbolIds.add(symbol.getFullyQualifiedName().length > 0 ? hashSymbol(symbol) : -1);
    }
  }

  isIdentifierTainted(identifier: Identifier): boolean {
    const symbol = identifier.getSymbol();
    if (symbol === undefined) {
      return false;
    }
    return this.taintedSymbolIds.has(hashSymbol(symbol));
  }

  clearIdentifierTaint(identifier: Identifier): void {
    const symbol = identifier.getSymbol();
    if (symbol !== undefined) {
      this.taintedSymbolIds.delete(hashSymbol(symbol));
    }
  }

  markQualifiedNameTainted(name: string): void {
    this.taintedQualifiedNames.add(name);
  }

  isQualifiedNameTainted(name: string): boolean {
    return this.taintedQualifiedNames.has(name);
  }

  /**
   * Merges another state's taint markings into this one. Used after
   * resolving a direct call into a callee's body: the callee's parameters
   * and locals are tracked in a separate `TaintState` during the inner walk
   * (so the callee's own locals don't leak back into the caller's names),
   * but their taint still needs to be visible to the top-level analyzer
   * when it later checks whether a sink argument *inside that callee body*
   * is tainted.
   */
  mergeFrom(other: TaintState): void {
    for (const id of other.taintedSymbolIds) {
      this.taintedSymbolIds.add(id);
    }
    for (const name of other.taintedQualifiedNames) {
      this.taintedQualifiedNames.add(name);
    }
  }

  hasVisitedFunction(id: number): boolean {
    return this.visitedFunctions.has(id);
  }

  markFunctionVisited(id: number): void {
    this.visitedFunctions.add(id);
  }
}

function hashSymbol(symbol: { getDeclarations(): Node[] }): number {
  const decl = symbol.getDeclarations()[0];
  if (decl === undefined) {
    return -1;
  }
  return decl.getPos();
}

/**
 * Returns true if `node` is, or is built from, a value the given `TaintState`
 * currently considers tainted. This is the recursive "is this expression
 * tainted" check used by every propagation rule below. It handles:
 *   - the source node itself
 *   - a tainted identifier reference
 *   - a template literal / binary `+` string concatenation containing a
 *     tainted sub-expression
 *   - a tainted property access (`obj.field` where `obj.field` was marked)
 *   - a call to a statically resolvable function/arrow whose return value is
 *     itself tainted (checked lazily, see `resolveCallTaint`)
 */
export function isExpressionTainted(
  node: Node,
  state: TaintState,
  sourceNode: Node,
  sanitizers: SanitizerConfig,
): boolean {
  if (node === sourceNode) {
    return true;
  }

  if (node.isKind(SyntaxKind.ParenthesizedExpression) || node.isKind(SyntaxKind.AwaitExpression)) {
    return isExpressionTainted(node.getExpression(), state, sourceNode, sanitizers);
  }

  if (node.isKind(SyntaxKind.Identifier)) {
    return state.isIdentifierTainted(node);
  }

  if (node.isKind(SyntaxKind.PropertyAccessExpression)) {
    const qualifiedName = node.getText();
    if (state.isQualifiedNameTainted(qualifiedName)) {
      return true;
    }
    return isExpressionTainted(node.getExpression(), state, sourceNode, sanitizers);
  }

  if (node.isKind(SyntaxKind.TemplateExpression)) {
    return node
      .getTemplateSpans()
      .some((span) => isExpressionTainted(span.getExpression(), state, sourceNode, sanitizers));
  }

  if (node.isKind(SyntaxKind.BinaryExpression) && node.getOperatorToken().getText() === "+") {
    return (
      isExpressionTainted(node.getLeft(), state, sourceNode, sanitizers) ||
      isExpressionTainted(node.getRight(), state, sourceNode, sanitizers)
    );
  }

  if (node.isKind(SyntaxKind.CallExpression)) {
    const calleeText = node.getExpression().getText();
    if (sanitizers.functionNames.some((name) => calleeText === name || calleeText.endsWith(`.${name}`))) {
      return false;
    }
    return resolveCallTaint(node, state, sourceNode, sanitizers);
  }

  if (node.isKind(SyntaxKind.AsExpression) || node.isKind(SyntaxKind.NonNullExpression)) {
    return isExpressionTainted(node.getExpression(), state, sourceNode, sanitizers);
  }

  return false;
}

/**
 * Direct function-call argument-to-parameter propagation. Resolves the
 * callee to exactly one function/arrow declaration via `getSymbol()` /
 * `getDeclarations()`. If the callee is ambiguous (zero or more than one
 * declaration, i.e. overloaded or dynamically dispatched), taint does not
 * propagate through the call — this matches the scoped, documented
 * limitation: only a single statically-resolvable direct call is handled.
 */
function resolveCallTaint(
  call: Node & { getExpression(): Node; getArguments(): Node[] },
  state: TaintState,
  sourceNode: Node,
  sanitizers: SanitizerConfig,
): boolean {
  const calleeExpr = call.getExpression();
  if (!calleeExpr.isKind(SyntaxKind.Identifier)) {
    return false;
  }
  const symbol = calleeExpr.getSymbol();
  if (symbol === undefined) {
    return false;
  }
  const declarations = symbol.getDeclarations();
  const fnDecl = declarations.find(
    (d) => d.isKind(SyntaxKind.FunctionDeclaration) || d.isKind(SyntaxKind.VariableDeclaration),
  );
  if (fnDecl === undefined || declarations.length !== 1) {
    return false;
  }

  let fn: Node | undefined;
  if (fnDecl.isKind(SyntaxKind.FunctionDeclaration)) {
    fn = fnDecl;
  } else if (fnDecl.isKind(SyntaxKind.VariableDeclaration)) {
    const initializer = fnDecl.getInitializer();
    if (initializer?.isKind(SyntaxKind.ArrowFunction) || initializer?.isKind(SyntaxKind.FunctionExpression)) {
      fn = initializer;
    }
  }
  if (fn === undefined) {
    return false;
  }

  const fnId = fn.getPos();
  if (state.hasVisitedFunction(fnId)) {
    return false;
  }
  state.markFunctionVisited(fnId);

  const fnWithParams = fn as unknown as { getParameters(): Identifier[]; getBody?: () => Node | undefined };
  const params = fnWithParams.getParameters();
  const args = call.getArguments();

  const localState = new TaintState();
  let anyParamTainted = false;
  for (let i = 0; i < params.length; i++) {
    const param = params[i];
    const arg = args[i];
    if (param === undefined || arg === undefined) {
      continue;
    }
    if (isExpressionTainted(arg, state, sourceNode, sanitizers)) {
      const paramIdentifier = param.getFirstDescendantByKind(SyntaxKind.Identifier) ?? param;
      if (paramIdentifier.isKind(SyntaxKind.Identifier)) {
        localState.markIdentifierTainted(paramIdentifier);
        anyParamTainted = true;
      }
    }
  }
  if (!anyParamTainted) {
    return false;
  }

  // Ambient/overload declarations have no body; ts-morph's `getBody()`
  // throws rather than returning `undefined` for those, so guard here too.
  let body: Node | undefined;
  try {
    body = fnWithParams.getBody?.();
  } catch {
    return false;
  }
  if (body === undefined) {
    return false;
  }

  // Use the tainted parameter itself as the "source" for the inner walk so
  // that assignments/returns inside the callee body are tracked relative to
  // it, then check whether the callee returns a tainted expression.
  const taintedParamIdentifier = params
    .map((p) => p.getFirstDescendantByKind(SyntaxKind.Identifier) ?? p)
    .find((p): p is Identifier => p.isKind(SyntaxKind.Identifier) && localState.isIdentifierTainted(p));

  if (taintedParamIdentifier === undefined) {
    return false;
  }

  propagateThroughStatements(body, localState, taintedParamIdentifier, sanitizers);

  // Merge the callee's taint markings (its tainted parameter and any
  // locals/properties derived from it) back into the caller's state. This
  // is what lets the top-level analyzer later recognize a sink argument
  // *inside this callee's body* as tainted when it checks sink nodes
  // against the state produced by walking the call site's enclosing scope.
  state.mergeFrom(localState);

  const returnStatements = body.getDescendantsOfKind(SyntaxKind.ReturnStatement);
  return returnStatements.some((ret) => {
    const returnExpr = ret.getExpression();
    return returnExpr !== undefined && isExpressionTainted(returnExpr, localState, taintedParamIdentifier, sanitizers);
  });
}

/**
 * Walks the statements of a function/block body in order, updating `state`
 * for direct assignments, object property assignments, and sanitizer
 * reassignments, relative to the given `sourceNode` taint origin. This is
 * also used by the top-level analyzer to walk an entire source file.
 */
export function propagateThroughStatements(
  container: Node,
  state: TaintState,
  sourceNode: Node,
  sanitizers: SanitizerConfig,
): void {
  const statements = container.isKind(SyntaxKind.Block) ? container.getStatements() : [container];

  for (const statement of statements) {
    // const b = a;  /  let b = a;
    if (statement.isKind(SyntaxKind.VariableStatement)) {
      for (const decl of statement.getDeclarationList().getDeclarations()) {
        const initializer = decl.getInitializer();
        if (initializer === undefined) {
          continue;
        }
        const nameNode = decl.getNameNode();

        // const obj = { field: tainted, other: "x" } -- mark obj.field
        // tainted per-property (qualified name), the object-literal
        // equivalent of `obj.field = tainted` assignment propagation, not
        // the whole `obj` reference.
        if (initializer.isKind(SyntaxKind.ObjectLiteralExpression) && nameNode.isKind(SyntaxKind.Identifier)) {
          for (const property of initializer.getProperties()) {
            if (!property.isKind(SyntaxKind.PropertyAssignment)) {
              continue;
            }
            const propertyValue = property.getInitializer();
            if (propertyValue !== undefined && isExpressionTainted(propertyValue, state, sourceNode, sanitizers)) {
              state.markQualifiedNameTainted(`${nameNode.getText()}.${property.getName()}`);
            }
          }
          continue;
        }

        if (isExpressionTainted(initializer, state, sourceNode, sanitizers)) {
          if (nameNode.isKind(SyntaxKind.Identifier)) {
            state.markIdentifierTainted(nameNode);
          }
        }
      }
    }

    // b = a;  /  b = sanitize(b);  /  obj.field = a;
    if (statement.isKind(SyntaxKind.ExpressionStatement)) {
      const expr = statement.getExpression();
      if (expr.isKind(SyntaxKind.BinaryExpression) && expr.getOperatorToken().getText() === "=") {
        const left = expr.getLeft();
        const right = expr.getRight();
        const rightTainted = isExpressionTainted(right, state, sourceNode, sanitizers);

        if (left.isKind(SyntaxKind.Identifier)) {
          if (rightTainted) {
            state.markIdentifierTainted(left);
          } else {
            // Reassignment to a non-tainted value clears taint — this is how
            // a sanitizer idiom (`x = sanitize(x)`) is recognized: the
            // sanitizer call itself returns false from isExpressionTainted
            // (see the sanitizer short-circuit above), so the reassignment
            // here clears the prior taint.
            state.clearIdentifierTaint(left);
          }
        } else if (left.isKind(SyntaxKind.PropertyAccessExpression)) {
          const qualifiedName = left.getText();
          if (rightTainted) {
            state.markQualifiedNameTainted(qualifiedName);
          }
        }
      } else {
        // A bare call statement, e.g. a call whose side effects we don't
        // model. Still walk into it in case it's a call whose body we can
        // resolve, purely so `visitedFunctions` bookkeeping and any
        // eventual sink-matching against this expression works uniformly.
        isExpressionTainted(expr, state, sourceNode, sanitizers);
      }
    }

    // Recurse into nested blocks (if/for/while bodies) without branch
    // sensitivity: a sanitizer applied in only one branch is treated the
    // same as everywhere, matching the documented control-flow limitation.
    if (statement.isKind(SyntaxKind.IfStatement)) {
      const thenStatement = statement.getThenStatement();
      propagateThroughStatements(thenStatement, state, sourceNode, sanitizers);
      const elseStatement = statement.getElseStatement();
      if (elseStatement !== undefined) {
        propagateThroughStatements(elseStatement, state, sourceNode, sanitizers);
      }
    }
    if (statement.isKind(SyntaxKind.Block)) {
      propagateThroughStatements(statement, state, sourceNode, sanitizers);
    }
  }
}

export { TaintState };
