#!/usr/bin/env node
/**
 * Command-line entry point. Usage:
 *
 *   npx tsx src/cli.ts "fixtures/**\/*.ts"
 *   npx tsx src/cli.ts "corpus/ai-chatbot/**\/*.ts" --json
 *
 * Prints one line per finding by default, or a JSON array with `--json`.
 * Exit code is 0 regardless of finding count (this is a report tool, not a
 * CI gate) unless the glob matches zero files, which exits 1 as a signal
 * that the scan likely didn't run against what was intended.
 */

import { analyzePaths, type Finding } from "./analyzer.js";

function formatFinding(finding: Finding): string {
  const relPath = finding.filePath;
  return (
    `${relPath}:${finding.sinkLine}  [${finding.ruleId}]\n` +
    `  source (line ${finding.sourceLine}): ${finding.sourceDescription}\n` +
    `  sink   (line ${finding.sinkLine}): ${finding.sinkDescription}\n` +
    `  tainted argument: ${finding.sinkSnippet}`
  );
}

function main(): void {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes("--json");
  const patterns = args.filter((a: string) => a !== "--json");

  if (patterns.length === 0) {
    process.stderr.write("Usage: ts-llm-taint <glob...> [--json]\n");
    process.exit(1);
  }

  const findings = analyzePaths(patterns);

  if (jsonOutput) {
    process.stdout.write(`${JSON.stringify(findings, null, 2)}\n`);
  } else {
    if (findings.length === 0) {
      process.stdout.write("No findings.\n");
    } else {
      for (const finding of findings) {
        process.stdout.write(`${formatFinding(finding)}\n\n`);
      }
    }
    process.stdout.write(`Total findings: ${findings.length}\n`);
  }
}

main();
