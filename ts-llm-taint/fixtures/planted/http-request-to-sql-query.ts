// PLANTED FLAW: an HTTP request parameter is string-templated directly into
// a SQL query string, then passed to a db.query() call. Classic SQL
// injection.
//
// Expected: 1 finding (http-request-to-sql-query).

import type { Request } from "express";

interface Db {
  query(sql: string): Promise<unknown>;
}

function findUser(req: Request, db: Db): Promise<unknown> {
  const username = req.query;
  const sql = `SELECT * FROM users WHERE username = '${username}'`;
  return db.query(sql);
}

export { findUser };
