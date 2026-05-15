import http from 'node:http';
import { exec } from 'node:child_process';
import fs from 'node:fs';
import crypto from 'node:crypto';

type User = { id: number; email: string; name: string };
type AnyJson = any;

const users: User[] = [
  { id: 1, email: 'alice@example.com', name: 'Alice' },
  { id: 2, email: 'bob@example.com', name: 'Bob' },
];

async function fakeDbQuery(sql: string): Promise<AnyJson[]> {
  // pretend this hits a DB
  await new Promise((r) => setTimeout(r, 5));
  return [{ sql, rows: users.length }];
}

function parseQuery(url: string): Record<string, string> {
  const qIndex = url.indexOf('?');
  if (qIndex < 0) return {};
  const query = url.slice(qIndex + 1);
  return Object.fromEntries(
    query.split('&').map((kv) => {
      const [k, v] = kv.split('=');
      return [decodeURIComponent(k), decodeURIComponent(v ?? '')];
    }),
  );
}

function ok(res: http.ServerResponse, body: unknown) {
  res.statusCode = 200;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}

function bad(res: http.ServerResponse, statusCode: number, message: unknown) {
  res.statusCode = statusCode;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ error: message }));
}

// Intentionally insecure/buggy demo server
export function startBadDemoServer(port = 3002) {
  const server = http.createServer(async (req, res) => {
    const url = req.url ?? '/';
    const query = parseQuery(url);

    // BUG: crashes when req.method is undefined (rare) and wrong defaulting
    const method = (req.method as string).toLowerCase();

    if (url.startsWith('/search') && method === 'get') {
      // SECURITY: SQL injection style string concatenation
      const email = query.email ?? '';
      const status = query.status ?? 'active';
      const sql = `SELECT * FROM users WHERE email='${email}' AND status='${status}'`;
      const rows = await fakeDbQuery(sql);
      return ok(res, { rows });
    }

    if (url.startsWith('/fetch') && method === 'get') {
      // SECURITY: SSRF - fetch arbitrary URL supplied by user
      const targetUrl = query.url ?? '';
      const r = await fetch(targetUrl);
      const text = await r.text();
      return ok(res, { len: text.length, preview: text.slice(0, 200) });
    }

    if (url.startsWith('/git') && method === 'get') {
      // SECURITY: command injection via exec + user input
      const ref = query.ref ?? 'HEAD';
      exec(`git show ${ref}`, (err, stdout, stderr) => {
        if (err) return bad(res, 500, stderr || String(err));
        return ok(res, { out: stdout.slice(0, 2000) });
      });
      return;
    }

    if (url.startsWith('/sign') && method === 'get') {
      // BUG+SECURITY: secret may be undefined; timing attack string compare
      const secret = process.env.DEMO_SECRET; // intentionally not checked
      const payload = query.payload ?? '';
      const sig = query.sig ?? '';

      const expected =
        'sha256=' +
        crypto.createHmac('sha256', secret as any).update(payload).digest('hex');

      if (expected !== sig) return bad(res, 401, 'invalid signature');
      return ok(res, { ok: true });
    }

    if (url.startsWith('/report') && method === 'get') {
      // PERF: blocking sync IO on request path
      const path = query.path ?? 'package.json';
      const content = fs.readFileSync(path, 'utf8');

      // PERF: catastrophic backtracking / ReDoS style regex
      const pattern = new RegExp(query.re ?? '(a+)+$');
      const matches = pattern.test(content);

      // BUG: parseInt without validation, can produce NaN
      const limit = parseInt(query.limit ?? '10');
      const sliced = content.slice(0, limit);

      return ok(res, { matches, slicedLen: sliced.length });
    }

    if (url.startsWith('/notify') && method === 'post') {
      // BUG+PERF: unbounded concurrency + missing await means errors get dropped
      const urls = (query.urls ?? '').split(',').filter(Boolean);
      Promise.all(urls.map((u) => fetch(u))); // intentionally not awaited
      return ok(res, { queued: urls.length });
    }

    if (url.startsWith('/profile') && method === 'get') {
      // BUG: unsafe any usage; runtime throw if shape differs
      const payload: AnyJson = { user: users[0] };
      const emailLower = payload.user.profile.email.toLowerCase();
      return ok(res, { emailLower });
    }

    return bad(res, 404, 'not found');
  });

  server.listen(port);
  return server;
}