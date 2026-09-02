// PLANTED FLAW: an HTTP request value is used verbatim as the __html of a
// dangerouslySetInnerHTML prop, with no escaping. If the request value
// contains attacker-controlled HTML/script, this is a stored/reflected XSS
// path.
//
// Expected: 1 finding (http-request-to-unsanitized-render).

import type { Request } from "express";

function buildProps(req: Request): { dangerouslySetInnerHTML: { __html: string } } {
  const rawHtml = req.body;
  return { dangerouslySetInnerHTML: { __html: rawHtml } };
}

export { buildProps };
