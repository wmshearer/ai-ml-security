// CLEAN adversarial near-miss (must NOT be flagged): the SQL query string is
// a fixed parameterized query (`$1` placeholder); the request value is
// passed as a separate query parameter, never templated into the SQL
// string itself.
//
// Expected: 0 findings.

import type { Request } from "express";

interface Db {
  query(sql: string, params?: unknown[]): Promise<unknown>;
}

function findUser(req: Request, db: Db): Promise<unknown> {
  const username = req.query;
  const sql = "SELECT * FROM users WHERE username = $1";
  return db.query(sql, [username]);
}

export { findUser };
