// CLEAN (must NOT be flagged): the request value is sanitized and
// reassigned before it is templated into the SQL string.
//
// Expected: 0 findings.

import type { Request } from "express";

interface Db {
  query(sql: string): Promise<unknown>;
}

declare function sanitize(input: unknown): string;

function findUser(req: Request, db: Db): Promise<unknown> {
  let username = req.query;
  username = sanitize(username) as unknown as typeof username;
  const sql = `SELECT * FROM users WHERE username = '${username}'`;
  return db.query(sql);
}

export { findUser };
