// CLEAN adversarial near-miss (must NOT be flagged): eval() is called with
// a hardcoded expression, no external input at all.
//
// Expected: 0 findings.

function computeConstant(): unknown {
  return eval("1 + 1");
}

export { computeConstant };
