/**
 * Taint sources for LLM applications.
 *
 * A "source" is a place in the code where untrusted data enters the program:
 * an HTTP request body, a user chat message, a document pulled back by a
 * retriever, or the result of a tool call the model itself triggered. None of
 * that data should be treated as a trusted instruction without a check first.
 *
 * Each `SourceRule` recognizes one syntactic shape a source can take. The
 * analyzer walks the AST (the parsed tree structure of the source file) once,
 * asking every rule in this list "does this node match you," and any match
 * becomes the origin of a taint trace.
 */

import type { CallExpression, Node, PropertyAccessExpression } from "ts-morph";
import { SyntaxKind } from "ts-morph";

/** Category of untrusted input, used to group findings and label traces. */
export type SourceCategory =
  | "http-request"
  | "user-message"
  | "retrieved-document"
  | "tool-result"
  | "env-or-file";

/** A single recognized taint source in the AST. */
export interface TaintSource {
  readonly category: SourceCategory;
  /** The AST node that represents the untrusted value itself. */
  readonly node: Node;
  /** Short human-readable description of why this node is a source. */
  readonly description: string;
}

/**
 * A rule that recognizes one syntactic source shape. `match` returns a
 * `TaintSource` when `node` is an instance of the shape this rule looks for,
 * or `undefined` otherwise. Rules are intentionally narrow and composable
 * rather than one large matcher, so each shape can be tested independently.
 */
export interface SourceRule {
  readonly id: string;
  readonly category: SourceCategory;
  match(node: Node): TaintSource | undefined;
}

function isPropertyAccessNamed(
  node: Node,
  objectNames: readonly string[],
  propertyNames: readonly string[],
): node is PropertyAccessExpression {
  if (!node.isKind(SyntaxKind.PropertyAccessExpression)) {
    return false;
  }
  const propertyName = node.getName();
  if (!propertyNames.includes(propertyName)) {
    return false;
  }
  const objectText = node.getExpression().getText();
  return objectNames.some((name) => objectText === name || objectText.endsWith(`.${name}`));
}

function isCallNamed(node: Node, calleeNames: readonly string[]): node is CallExpression {
  if (!node.isKind(SyntaxKind.CallExpression)) {
    return false;
  }
  const calleeText = node.getExpression().getText();
  return calleeNames.some((name) => calleeText === name || calleeText.endsWith(`.${name}`));
}

/**
 * `req.body`, `req.query`, `req.params` — Express-style request accessors.
 * Also matches Next.js-style `request.body` on a route handler parameter
 * named `request`.
 */
const httpRequestPropertyRule: SourceRule = {
  id: "http-request-property",
  category: "http-request",
  match(node) {
    if (!isPropertyAccessNamed(node, ["req", "request"], ["body", "query", "params"])) {
      return undefined;
    }
    return {
      category: "http-request",
      node,
      description: `HTTP request property \`${node.getText()}\``,
    };
  },
};

/** `request.json()` / `request.formData()` — Next.js route handler bodies. */
const httpRequestJsonCallRule: SourceRule = {
  id: "http-request-json-call",
  category: "http-request",
  match(node) {
    if (!isCallNamed(node, ["request.json", "req.json", "request.formData", "req.formData"])) {
      return undefined;
    }
    return {
      category: "http-request",
      node,
      description: `HTTP request body call \`${node.getText()}\``,
    };
  },
};

/**
 * `searchParams.get(...)` on a Next.js `request.nextUrl.searchParams` or a
 * plain `URLSearchParams`-shaped object.
 */
const searchParamsGetRule: SourceRule = {
  id: "search-params-get",
  category: "http-request",
  match(node) {
    if (!node.isKind(SyntaxKind.CallExpression)) {
      return undefined;
    }
    const expr = node.getExpression();
    if (!expr.isKind(SyntaxKind.PropertyAccessExpression)) {
      return undefined;
    }
    if (expr.getName() !== "get") {
      return undefined;
    }
    if (!expr.getExpression().getText().toLowerCase().includes("searchparams")) {
      return undefined;
    }
    return {
      category: "http-request",
      node,
      description: `URL search param read \`${node.getText()}\``,
    };
  },
};

/**
 * An element of a `messages` array whose `role` is `"user"` — the LangChain.js
 * `HumanMessage`/AI SDK `UserModelMessage` shape. Matches on the object
 * literal itself: `{ role: "user", content: ... }`.
 */
const userMessageObjectRule: SourceRule = {
  id: "user-message-object",
  category: "user-message",
  match(node) {
    if (!node.isKind(SyntaxKind.ObjectLiteralExpression)) {
      return undefined;
    }
    const roleProp = node.getProperty("role");
    if (roleProp === undefined || !roleProp.isKind(SyntaxKind.PropertyAssignment)) {
      return undefined;
    }
    const roleValue = roleProp.getInitializer();
    if (roleValue === undefined || roleValue.getText().replace(/['"]/g, "") !== "user") {
      return undefined;
    }
    const contentProp = node.getProperty("content");
    if (contentProp === undefined || !contentProp.isKind(SyntaxKind.PropertyAssignment)) {
      return undefined;
    }
    const contentValue = contentProp.getInitializer();
    if (contentValue === undefined) {
      return undefined;
    }
    // A hardcoded string/no-substitution template literal is not untrusted
    // input, even inside a `{ role: "user", ... }` shape -- same false-
    // positive class documented on `humanMessageConstructorRule` above.
    if (
      contentValue.isKind(SyntaxKind.StringLiteral) ||
      contentValue.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)
    ) {
      return undefined;
    }
    return {
      category: "user-message",
      node: contentValue,
      description: `user-role message content \`${contentValue.getText()}\``,
    };
  },
};

/**
 * `new HumanMessage(...)` argument — LangChain.js's user-message
 * constructor. A hardcoded string/no-substitution template literal argument
 * is excluded: a developer-written constant is not untrusted input, even
 * though `HumanMessage` is conceptually "the user's turn." Without this
 * exclusion, every `new HumanMessage("some fixed prompt")` in a codebase
 * would be misreported as a taint source, which is a real false-positive
 * class this project measures rather than hides (see FINDINGS.md).
 */
const humanMessageConstructorRule: SourceRule = {
  id: "human-message-constructor-arg",
  category: "user-message",
  match(node) {
    if (!node.isKind(SyntaxKind.NewExpression)) {
      return undefined;
    }
    if (node.getExpression().getText() !== "HumanMessage") {
      return undefined;
    }
    const arg = node.getArguments()[0];
    if (arg === undefined) {
      return undefined;
    }
    if (arg.isKind(SyntaxKind.StringLiteral) || arg.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
      return undefined;
    }
    return {
      category: "user-message",
      node: arg,
      description: `HumanMessage constructor argument \`${arg.getText()}\``,
    };
  },
};

/**
 * A retriever/vector-store call whose result is retrieved document content:
 * `.invoke(...)`, `.getRelevantDocuments(...)`, `.similaritySearch(...)` on
 * anything named/typed like a retriever or vector store.
 */
const retrieverCallRule: SourceRule = {
  id: "retriever-call-result",
  category: "retrieved-document",
  match(node) {
    if (!node.isKind(SyntaxKind.CallExpression)) {
      return undefined;
    }
    const expr = node.getExpression();
    if (!expr.isKind(SyntaxKind.PropertyAccessExpression)) {
      return undefined;
    }
    const methodName = expr.getName();
    const retrieverMethods = ["getRelevantDocuments", "similaritySearch", "similaritySearchWithScore"];
    const objectText = expr.getExpression().getText().toLowerCase();
    const looksLikeRetriever =
      objectText.includes("retriever") || objectText.includes("vectorstore") || objectText.includes("vectorStore".toLowerCase());
    if (retrieverMethods.includes(methodName)) {
      return {
        category: "retrieved-document",
        node,
        description: `retriever call \`${node.getText()}\``,
      };
    }
    if (methodName === "invoke" && looksLikeRetriever) {
      return {
        category: "retrieved-document",
        node,
        description: `retriever \`.invoke()\` call \`${node.getText()}\``,
      };
    }
    return undefined;
  },
};

/**
 * The `execute` callback's return value in a Vercel AI SDK `tool({ execute })`
 * definition, and the `func` return value in LangChain.js's `tool(func, ...)`.
 * We approximate this by matching `return <expr>` statements inside a
 * function expression/arrow function assigned to a property named `execute`,
 * or a function passed as the first argument to `tool(...)`.
 */
const toolResultReturnRule: SourceRule = {
  id: "tool-result-return",
  category: "tool-result",
  match(node) {
    if (!node.isKind(SyntaxKind.ReturnStatement)) {
      return undefined;
    }
    const returnExpr = node.getExpression();
    if (returnExpr === undefined) {
      return undefined;
    }
    const fn = node.getFirstAncestor(
      (a) => a.isKind(SyntaxKind.FunctionExpression) || a.isKind(SyntaxKind.ArrowFunction),
    );
    if (fn === undefined) {
      return undefined;
    }
    const parent = fn.getParent();
    let inToolDefinition = false;
    if (parent?.isKind(SyntaxKind.PropertyAssignment) && parent.getName() === "execute") {
      inToolDefinition = true;
    }
    if (parent?.isKind(SyntaxKind.CallExpression)) {
      const calleeText = parent.getExpression().getText();
      if (calleeText === "tool" || calleeText.endsWith(".tool")) {
        inToolDefinition = true;
      }
    }
    if (!inToolDefinition) {
      return undefined;
    }
    return {
      category: "tool-result",
      node: returnExpr,
      description: `tool execute/func return value \`${returnExpr.getText()}\``,
    };
  },
};

/** A `ToolMessage` constructor's content argument fed back into a conversation. */
const toolMessageConstructorRule: SourceRule = {
  id: "tool-message-constructor-arg",
  category: "tool-result",
  match(node) {
    if (!node.isKind(SyntaxKind.NewExpression)) {
      return undefined;
    }
    if (node.getExpression().getText() !== "ToolMessage") {
      return undefined;
    }
    const arg = node.getArguments()[0];
    if (arg === undefined) {
      return undefined;
    }
    // Same false-positive exclusion as `humanMessageConstructorRule`: a
    // hardcoded literal is not untrusted tool output.
    if (arg.isKind(SyntaxKind.StringLiteral) || arg.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
      return undefined;
    }
    return {
      category: "tool-result",
      node: arg,
      description: `ToolMessage constructor argument \`${arg.getText()}\``,
    };
  },
};

/** All built-in source rules, applied in this order. */
export const sourceRules: readonly SourceRule[] = [
  httpRequestPropertyRule,
  httpRequestJsonCallRule,
  searchParamsGetRule,
  userMessageObjectRule,
  humanMessageConstructorRule,
  retrieverCallRule,
  toolResultReturnRule,
  toolMessageConstructorRule,
];
