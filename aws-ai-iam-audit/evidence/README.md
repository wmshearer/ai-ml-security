# Evidence directory

Every file in this directory is real, captured tool output. Nothing here is
hand-written or summarized without a backing file.

## cloudsplaining/

One `<PolicyName>.txt` file per fetched policy. Each file begins with the
exact command run, followed by the tool's real stdout+stderr, followed by an
`EXIT_CODE:` line.

Command shape used for all files:

```
.venv/bin/cloudsplaining scan-policy-file --input-file policies/<PolicyName>.json -v
```

## parliament/

One `<PolicyName>.txt` (human-readable) and one `<PolicyName>.jsonl`
(one JSON object per line, one line per finding) file per fetched policy.

Parliament reads its target policy from stdin in this project because the
`--file` flag and the tool's own stdin-detection logic (`sys.stdin.isatty()`)
conflict when run from a non-interactive shell (any CI runner, this build
environment, etc.) -- passing `--file` in that context makes parliament think
stdin is also being used and it exits with an argument error. Piping the
policy JSON to stdin avoids this entirely and is a supported, documented
invocation of the tool.

Command shape used for all files:

```
.venv/bin/parliament < policies/<PolicyName>.json            # text output
.venv/bin/parliament --json < policies/<PolicyName>.json     # JSON Lines output
```

A `pkg_resources` deprecation warning from setuptools appears in the text
output; this is expected, harmless, and left in place unedited since these
are unedited captures of real output. It happens because parliament imports
`pkg_resources` for plugin discovery and modern setuptools has deprecated
that module.

## policy_sentry/

Output of `policy_sentry query action-table` for specific IAM actions
referenced in the analysis (`iam:PassRole`, `s3:GetObject`,
`sagemaker:CreateTrainingJob`, `sagemaker:InvokeEndpoint`). This shows AWS's
own documented resource ARN formats and condition keys for each action --
used to establish that a scoped, non-wildcard resource format is available
for these actions (so the managed policies' choice of a wildcard is a choice,
not a technical necessity).

## analyze_findings.json

Structured output of `src/analyze.py`, the custom analyzer written for this
project. Regenerate with:

```
.venv/bin/python src/analyze.py
```
