/**
 * Taint sinks for LLM applications.
 *
 * A "sink" is a place where it is dangerous for untrusted data to arrive
 * without having been checked first: a place that gets treated as a trusted
 * instruction by the model (a system prompt, a tool description), or a place
 * that executes/reads/writes something (`eval`, a shell command, a file
 * path, a SQL query).
 *
 * Each `SinkRule` recognizes one syntactic call/constructor shape and, given
 * a matching node, reports which argument position(s) are the dangerous
 * slot(s). The propagation engine (`propagation.ts`) checks whether a
 * tainted value can reach one of those argument slots.
 */

import type { CallExpression, Node, NewExpression } from "ts-morph";
import { SyntaxKind } from "ts-morph";

/** Category of dangerous location, used to group findings. */
export type SinkCategory =
  | "prompt-construction"
  | "code-execution"
  | "shell-execution"
  | "sql-query"
  | "file-path"
  | "unsanitized-render";

/** One argument slot of a sink call/constructor that is dangerous if tainted. */
export interface SinkArgument {
  readonly node: Node;
  readonly argIndex: number;
}

/** A single recognized taint sink in the AST. */
export interface TaintSink {
  readonly category: SinkCategory;
  /** The call or constructor expression that is the sink itself. */
  readonly callNode: Node;
  /** The specific argument slot(s) that are dangerous if tainted. */
  readonly dangerousArguments: readonly SinkArgument[];
  readonly description: string;
}

/** A rule that recognizes one syntactic sink shape. */
export interface SinkRule {
  readonly id: string;
  readonly category: SinkCategory;
  match(node: Node): TaintSink | undefined;
}

function argAt(call: CallExpression | NewExpression, index: number): Node | undefined {
  return call.getArguments()[index];
}

/** `new SystemMessage(...)` / `new HumanMessage(...)` constructor argument. */
const chatMessageConstructorRule: SinkRule = {
  id: "chat-message-constructor",
  category: "prompt-construction",
  match(node) {
    if (!node.isKind(SyntaxKind.NewExpression)) {
      return undefined;
    }
    const calleeName = node.getExpression().getText();
    if (calleeName !== "SystemMessage" && calleeName !== "HumanMessage") {
      return undefined;
    }
    const arg = argAt(node, 0);
    if (arg === undefined) {
      return undefined;
    }
    return {
      category: "prompt-construction",
      callNode: node,
      dangerousArguments: [{ node: arg, argIndex: 0 }],
      description: `${calleeName} constructor argument`,
    };
  },
};

/**
 * `ChatPromptTemplate.fromMessages([...])` — each element of the messages
 * array is a dangerous slot. We report the whole array literal as the
 * sink argument; the propagation engine checks whether the tainted value
 * flows into any element of it.
 */
const chatPromptTemplateFromMessagesRule: SinkRule = {
  id: "chat-prompt-template-from-messages",
  category: "prompt-construction",
  match(node) {
    if (!node.isKind(SyntaxKind.CallExpression)) {
      return undefined;
    }
    const expr = node.getExpression();
    if (!expr.isKind(SyntaxKind.PropertyAccessExpression)) {
      return undefined;
    }
    if (expr.getExpression().getText() !== "ChatPromptTemplate" || expr.getName() !== "fromMessages") {
      return undefined;
    }
    const arg = argAt(node, 0);
    if (arg === undefined) {
      return undefined;
    }
    return {
      category: "prompt-construction",
      callNode: node,
      dangerousArguments: [{ node: arg, argIndex: 0 }],
      description: "ChatPromptTemplate.fromMessages argument",
    };
  },
};

/**
 * `generateText({...})` / `streamText({...})` — the `system`, `prompt`, and
 * `messages` properties of the options object are dangerous slots.
 */
const aiSdkGenerateCallRule: SinkRule = {
  id: "ai-sdk-generate-call",
  category: "prompt-construction",
  match(node) {
    if (!node.isKind(SyntaxKind.CallExpression)) {
      return undefined;
    }
    const calleeText = node.getExpression().getText();
    if (calleeText !== "generateText" && calleeText !== "streamText") {
      return undefined;
    }
    const optionsArg = argAt(node, 0);
    if (optionsArg === undefined || !optionsArg.isKind(SyntaxKind.ObjectLiteralExpression)) {
      return undefined;
    }
    const dangerousArguments: SinkArgument[] = [];
    for (const propName of ["system", "prompt", "messages"]) {
      const prop = optionsArg.getProperty(propName);
      if (prop !== undefined && prop.isKind(SyntaxKind.PropertyAssignment)) {
        const value = prop.getInitializer();
        if (value !== undefined) {
          dangerousArguments.push({ node: value, argIndex: 0 });
        }
      }
    }
    if (dangerousArguments.length === 0) {
      return undefined;
    }
    return {
      category: "prompt-construction",
      callNode: node,
      dangerousArguments,
      description: `${calleeText} options (system/prompt/messages)`,
    };
  },
};

/**
 * `tool({ description, ... })` — the `description` field, for both the AI
 * SDK's `tool()` and LangChain.js's `tool(func, { description })`.
 *
 * NOTE: this is an UNVERIFIED sink for LangChain.js specifically. The
 * research brief (Section 3, item 2) flags that `tool().description` as a
 * CodeQL-modeled sink is confirmed for OpenAI's `@openai/agents` but not
 * present in CodeQL's own `langchain.model.yml` at time of writing. We
 * include it here as a plausible, analogous sink (a tool description does
 * reach the model's context in both frameworks) but the analyzer's own
 * output and this project's docs must say plainly that this specific
 * mapping is inferred, not independently confirmed against LangChain's own
 * sink list.
 */
const toolDescriptionRule: SinkRule = {
  id: "tool-description-field",
  category: "prompt-construction",
  match(node) {
    if (!node.isKind(SyntaxKind.PropertyAssignment)) {
      return undefined;
    }
    if (node.getName() !== "description") {
      return undefined;
    }
    const objectLiteral = node.getParent();
    if (!objectLiteral.isKind(SyntaxKind.ObjectLiteralExpression)) {
      return undefined;
    }
    const call = objectLiteral.getParent();
    let inToolCall = false;
    if (call?.isKind(SyntaxKind.CallExpression)) {
      const calleeText = call.getExpression().getText();
      if (calleeText === "tool" || calleeText.endsWith(".tool")) {
        inToolCall = true;
      }
    }
    if (!inToolCall) {
      return undefined;
    }
    const value = node.getInitializer();
    if (value === undefined) {
      return undefined;
    }
    return {
      category: "prompt-construction",
      callNode: node,
      dangerousArguments: [{ node: value, argIndex: 0 }],
      description: "tool() description field (UNVERIFIED sink mapping for LangChain.js, see docs)",
    };
  },
};

/** `eval(...)` / `new Function(...)`. */
const codeExecutionRule: SinkRule = {
  id: "code-execution",
  category: "code-execution",
  match(node) {
    if (node.isKind(SyntaxKind.CallExpression) && node.getExpression().getText() === "eval") {
      const arg = argAt(node, 0);
      if (arg === undefined) {
        return undefined;
      }
      return {
        category: "code-execution",
        callNode: node,
        dangerousArguments: [{ node: arg, argIndex: 0 }],
        description: "eval() argument",
      };
    }
    if (node.isKind(SyntaxKind.NewExpression) && node.getExpression().getText() === "Function") {
      const arg = argAt(node, 0);
      if (arg === undefined) {
        return undefined;
      }
      return {
        category: "code-execution",
        callNode: node,
        dangerousArguments: [{ node: arg, argIndex: 0 }],
        description: "new Function() argument",
      };
    }
    return undefined;
  },
};

/** `child_process.exec/execSync/spawn(...)` with a tainted command string. */
const SHELL_EXEC_NAMES = ["exec", "execSync", "spawn", "spawnSync"] as const;

const shellExecutionRule: SinkRule = {
  id: "shell-execution",
  category: "shell-execution",
  match(node) {
    if (!node.isKind(SyntaxKind.CallExpression)) {
      return undefined;
    }
    const expr = node.getExpression();

    // child_process.execSync(...) / cp.execSync(...)
    let methodName: string | undefined;
    if (expr.isKind(SyntaxKind.PropertyAccessExpression)) {
      methodName = expr.getName();
    } else if (expr.isKind(SyntaxKind.Identifier)) {
      // execSync(...) imported directly, e.g.
      // `import { execSync } from "node:child_process"`.
      methodName = expr.getText();
    }
    if (methodName === undefined || !SHELL_EXEC_NAMES.includes(methodName as (typeof SHELL_EXEC_NAMES)[number])) {
      return undefined;
    }
    const arg = argAt(node, 0);
    if (arg === undefined) {
      return undefined;
    }
    return {
      category: "shell-execution",
      callNode: node,
      dangerousArguments: [{ node: arg, argIndex: 0 }],
      description: `${methodName} command argument`,
    };
  },
};

/** A template-literal or concatenated SQL query passed to `.query(...)`. */
const sqlQueryRule: SinkRule = {
  id: "sql-query",
  category: "sql-query",
  match(node) {
    if (!node.isKind(SyntaxKind.CallExpression)) {
      return undefined;
    }
    const expr = node.getExpression();
    if (!expr.isKind(SyntaxKind.PropertyAccessExpression) || expr.getName() !== "query") {
      return undefined;
    }
    const arg = argAt(node, 0);
    if (arg === undefined) {
      return undefined;
    }
    return {
      category: "sql-query",
      callNode: node,
      dangerousArguments: [{ node: arg, argIndex: 0 }],
      description: "db.query() argument",
    };
  },
};

/** `fs.readFile/writeFile/readFileSync/writeFileSync(...)` path argument. */
const filePathRule: SinkRule = {
  id: "file-path",
  category: "file-path",
  match(node) {
    if (!node.isKind(SyntaxKind.CallExpression)) {
      return undefined;
    }
    const expr = node.getExpression();
    if (!expr.isKind(SyntaxKind.PropertyAccessExpression)) {
      return undefined;
    }
    const methodName = expr.getName();
    if (!["readFile", "writeFile", "readFileSync", "writeFileSync"].includes(methodName)) {
      return undefined;
    }
    const objectText = expr.getExpression().getText();
    if (objectText !== "fs" && !objectText.endsWith(".fs")) {
      return undefined;
    }
    const arg = argAt(node, 0);
    if (arg === undefined) {
      return undefined;
    }
    return {
      category: "file-path",
      callNode: node,
      dangerousArguments: [{ node: arg, argIndex: 0 }],
      description: `fs.${methodName} path argument`,
    };
  },
};

/** JSX `dangerouslySetInnerHTML={{ __html: ... }}`. */
const dangerouslySetInnerHtmlRule: SinkRule = {
  id: "dangerously-set-inner-html",
  category: "unsanitized-render",
  match(node) {
    if (!node.isKind(SyntaxKind.PropertyAssignment) || node.getName() !== "__html") {
      return undefined;
    }
    const value = node.getInitializer();
    if (value === undefined) {
      return undefined;
    }
    return {
      category: "unsanitized-render",
      callNode: node,
      dangerousArguments: [{ node: value, argIndex: 0 }],
      description: "dangerouslySetInnerHTML __html value",
    };
  },
};

/** All built-in sink rules, applied in this order. */
export const sinkRules: readonly SinkRule[] = [
  chatMessageConstructorRule,
  chatPromptTemplateFromMessagesRule,
  aiSdkGenerateCallRule,
  toolDescriptionRule,
  codeExecutionRule,
  shellExecutionRule,
  sqlQueryRule,
  filePathRule,
  dangerouslySetInnerHtmlRule,
];
