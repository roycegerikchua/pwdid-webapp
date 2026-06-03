const assert = require('node:assert/strict');

const base = process.env.BASE_URL || 'http://127.0.0.1:3015';
let cookie = '';

async function request(method, path, body, opts = {}) {
  const headers = body ? { 'Content-Type': 'application/json' } : {};
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(base + path, {
    method,
    redirect: opts.redirect || 'follow',
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  const text = await res.text();
  let payload;
  try { payload = JSON.parse(text); } catch { payload = text; }
  return { res, payload };
}

async function json(method, path, body) {
  const { res, payload } = await request(method, path, body);
  if (!res.ok) throw new Error(`${method} ${path} failed: ${res.status} ${JSON.stringify(payload)}`);
  return payload;
}

async function loginIfConfigured() {
  if (!process.env.SMOKE_USERNAME || !process.env.SMOKE_PASSWORD) return false;
  const form = new URLSearchParams({ username: process.env.SMOKE_USERNAME, password: process.env.SMOKE_PASSWORD });
  const res = await fetch(base + '/auth/login', {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  if (![302, 303].includes(res.status) || !cookie) throw new Error(`Login failed: HTTP ${res.status}`);
  return true;
}

(async () => {
  const health = await json('GET', '/health');
  assert.equal(health.ok, true);

  const unauth = await request('GET', '/pwdid/stats');
  assert.equal(unauth.res.status, 401);

  const loggedIn = await loginIfConfigured();
  if (!loggedIn) {
    console.log('Smoke tests passed:', { health: true, unauth_protection: true, authenticated_checks: 'skipped (set SMOKE_USERNAME/SMOKE_PASSWORD)' });
    return;
  }

  const me = await json('GET', '/api/me');
  assert.equal(me.success, true);
  assert.ok(me.user && me.user.username);
  assert.ok(me.user.branch_name || me.user.role === 'admin');

  const stats = await json('GET', '/pwdid/stats');
  assert.equal(stats.success, true);
  assert.equal(typeof stats.total, 'number');

  const lookup = await json('POST', '/pwdid/lookup', { id_number: '13-3902-000-0042275' });
  assert.equal(lookup.found, true);
  assert.equal(lookup.record.id_number, '13-3902-000-0042275');

  const list = await json('GET', '/pwdid/list?pageSize=3');
  assert.equal(list.success, true);
  assert.ok(Array.isArray(list.records));

  console.log('Smoke tests passed:', { user: me.user.username, branch: me.user.branch_name, total: stats.total, lookup: lookup.record.id_number, listed: list.records.length });
})().catch(err => { console.error(err); process.exit(1); });
