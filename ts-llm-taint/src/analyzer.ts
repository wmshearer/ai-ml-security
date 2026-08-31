/**
 * Top-level analyzer: wires sources, propagation, and sinks together over a
 * ts-morph `Project`, and produces a flat list of `Finding`s.
 *
 * The approach for each source file:
 *   1. Find every taint source in the file (`sources.ts`).
 *   2. For each source, walk the enclosing statements forward from the
 *      source's position, tracking which identifiers/qualified names become
 *      tainted (`propagation.ts`).
 *   3. Find every sink in the file (`sinks.ts`). For each sink's dangerous
 *      argument slot(s), check whether the expression there is tainted with
 *      respect to that source's propagation state.
 *   4. Every (source, sink) pair where the sink's argument is tainted is one
 *      `Finding`.
 *
 * This file-by-file, source-by-source design directly reflects the scoped
 * capability described in README.md: propagation is followed within a
 * function body and into one level of statically-resolvable direct function
 * calls, not across arbitrary call graphs or async boundaries.
 */

import { Project, type SourceFile, SyntaxKind, type Node } from "ts-morph";
import { sourceRules, type TaintSource } from "./sources.js";
import { sinkRules, type TaintSink } from "./sinks.js";
import { TaintState, isExpressionTainted, propagateThroughStatements, defaultSanitizers, type SanitizerConfig } from "./propagation.js";

/** One confirmed taint finding: a source that reaches a sink. */
export interface Finding {
  readonly ruleId: string;
  readonly sourceCategory: TaintSource["category"];
  readonly sinkCategory: TaintSink["category"];
  readonly filePath: string;
  readonly sourceLine: number;
  readonly sinkLine: number;
  readonly sourceDescription: string;
  readonly sinkDescription: string;
  /** Rendered snippet of the sink's dangerous argument, for reporting. */
  readonly sinkSnippet: string;
}

export interface AnalyzerOptions {
  readonly sanitizers?: SanitizerConfig;
}

/** Finds the nearest enclosing function body or the source file itself. */
function findEnclosingScope(node: Node): Node {
  const fn = node.getFirstAncestor(
    (a) =>
      a.isKind(SyntaxKind.FunctionDeclaration) ||
      a.isKind(SyntaxKind.FunctionExpression) ||
      a.isKind(SyntaxKind.ArrowFunction) ||
      a.isKind(SyntaxKind.MethodDeclaration),
  );
  if (fn === undefined) {
    return node.getSourceFile();
  }
  // Some function-shaped nodes (ambient declarations, overload signatures)
  // have no body; ts-morph's `getBody()` throws rather than returning
  // `undefined` in that case, so guard with a try/catch and fall back to
  // the whole source file.
  try {
    const bodied = fn as unknown as { getBody?: () => Node | undefined };
    const body = bodied.getBody !== undefined ? bodied.getBody() : undefined;
    return body ?? fn;
  } catch {
    return node.getSourceFile();
  }
}

/**
 * Runs the full source -> propagation -> sink pipeline against a single
 * source file and returns every finding.
 */
export function analyzeSourceFile(sourceFile: SourceFile, options: AnalyzerOptions = {}): Finding[] {
  const sanitizers = options.sanitizers ?? defaultSanitizers;
  const findings: Finding[] = [];

  const taintSources: TaintSource[] = [];
  sourceFile.forEachDescendant((node) => {
    for (const rule of sourceRules) {
      const match = rule.match(node);
      if (match !== undefined) {
        taintSources.push(match);
        break;
      }
    }
  });

  const taintSinks: TaintSink[] = [];
  sourceFile.forEachDescendant((node) => {
    for (const rule of sinkRules) {
      const match = rule.match(node);
      if (match !== undefined) {
        taintSinks.push(match);
        break;
      }
    }
  });

  for (const source of taintSources) {
    const scope = findEnclosingScope(source.node);
    const state = new TaintState();

    // Seed: if the source node is itself an identifier being declared
    // (e.g. `const body = req.body;` — the source rule matches `req.body`,
    // which becomes the initializer), propagateThroughStatements will pick
    // up the declaration naturally on its own pass below. We still run a
    // scope-wide propagation pass using this source's node as the taint
    // origin so any assignment/property-write reachable from it is tracked.
    propagateThroughStatements(scope, state, source.node, sanitizers);

    for (const sink of taintSinks) {
      // Only consider sinks in the same file; cross-file propagation is out
      // of scope (see README "Scope").
      for (const dangerousArg of sink.dangerousArguments) {
        if (isSinkArgumentTainted(dangerousArg.node, state, source.node, sanitizers)) {
          findings.push({
            ruleId: `${sourceCategoryToRuleFragment(source.category)}-to-${sink.category}`,
            sourceCategory: source.category,
            sinkCategory: sink.category,
            filePath: sourceFile.getFilePath(),
            sourceLine: source.node.getStartLineNumber(),
            sinkLine: sink.callNode.getStartLineNumber(),
            sourceDescription: source.description,
            sinkDescription: sink.description,
            sinkSnippet: dangerousArg.node.getText(),
          });
          break;
        }
      }
    }
  }

  return dedupeFindings(findings);
}

/**
 * A sink argument can be a single expression, or (for array-shaped sinks
 * like `ChatPromptTemplate.fromMessages([...])`) an array literal whose
 * elements each need checking.
 */
function isSinkArgumentTainted(argNode: Node, state: TaintState, sourceNode: Node, sanitizers: SanitizerConfig): boolean {
  if (argNode.isKind(SyntaxKind.ArrayLiteralExpression)) {
    return argNode.getElements().some((el) => isSinkArgumentTainted(el, state, sourceNode, sanitizers));
  }
  if (argNode.isKind(SyntaxKind.ObjectLiteralExpression)) {
    const contentProp = argNode.getProperty("content");
    if (contentProp?.isKind(SyntaxKind.PropertyAssignment)) {
      const value = contentProp.getInitializer();
      if (value !== undefined) {
        return isExpressionTainted(value, state, sourceNode, sanitizers);
      }
    }
    return false;
  }
  return isExpressionTainted(argNode, state, sourceNode, sanitizers);
}

function sourceCategoryToRuleFragment(category: TaintSource["category"]): string {
  return category;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.filePath}:${finding.sourceLine}:${finding.sinkLine}:${finding.ruleId}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(finding);
    }
  }
  return result;
}

/** Creates a ts-morph `Project` and analyzes every `.ts`/`.tsx` file matched by `globPatterns`. */
export function analyzePaths(globPatterns: string | string[], options: AnalyzerOptions = {}): Finding[] {
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    compilerOptions: {
      allowJs: false,
      jsx: 4 /* ts.JsxEmit.ReactJSX, avoided importing `typescript` directly here */,
    },
  });
  project.addSourceFilesAtPaths(globPatterns);

  const findings: Finding[] = [];
  for (const sourceFile of project.getSourceFiles()) {
    findings.push(...analyzeSourceFile(sourceFile, options));
  }
  return findings;
}
