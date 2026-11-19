import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { openDatabase } from '../src/database.js';
import { hashPassword } from '../src/security.js';
import { startServer } from '../src/server.js';

let directory; let db; let server; let origin; let dispatcher; let driver; let otherDriver;let serverDb;
const password = 'Correct horse battery 2030!';

async function createUser(email, role) {
  const id = randomUUID();
  db.prepare('INSERT INTO users (id,email,password_hash,role,is_active,created_at) VALUES (?, ?, ?, ?, 1, ?)')
    .run(id, email, await hashPassword(password), role, new Date().toISOString());
  return { id, email, role };
}

async function login(email, suppliedPassword = password) {
  const response = await fetch(`${origin}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: suppliedPassword }) });
  return { response, body: await response.json() };
}

async function request(path, token, options = {}) {
  const headers = new Headers(options.headers ?? {});
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (options.body && typeof options.body === 'string') headers.set('Content-Type', 'application/json');
  return fetch(`${origin}${path}`, { ...options, headers });
}

before(async () => {
  directory = mkdtempSync(join(tmpdir(), 'gml-shield-test-'));
  process.env.GML_SECRET_KEY_B64 = randomBytes(32).toString('base64');
  process.env.GML_AUDIT_KEY_B64 = randomBytes(32).toString('base64');
  process.env.GML_SESSION_KEY_B64 = randomBytes(32).toString('base64');
  db = openDatabase(join(directory, 'test.sqlite'));
  ({ server, db: serverDb } = startServer({ port: 0, host: '127.0.0.1', databasePath: join(directory, 'test.sqlite'), uploadDir: join(directory, 'uploads'), sessionTtlMs: 900_000 }));
  await once(server, 'listening');
  origin = `http://127.0.0.1:${server.address().port}`;
  dispatcher = await createUser('dispatcher@gml.example', 'DISPATCHER');
  driver = await createUser('driver@gml.example', 'DRIVER');
  otherDriver = await createUser('other@gml.example', 'DRIVER');
});

after(async () => {
  // Attendre la fermeture du serveur avant de fermer ses ressources.
  if (server?.listening) {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  // Fermer les deux connexions SQLite.
  serverDb?.close();
  db?.close();

  // Supprimer les fichiers après libération des ressources.
  if (directory) {
    rmSync(directory, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 100,
    });
  }
});

test('authenticates users, isolates assignments, encrypts access codes and records actions', async () => {
  const wrong = await login(dispatcher.email, 'incorrect');
  assert.equal(wrong.response.status, 401);
  const d = await login(dispatcher.email);
  assert.equal(d.response.status, 200);
  const driverLogin = await login(driver.email);
  const otherLogin = await login(otherDriver.email);
  const dispatcherToken = d.body.access_token;
  const driverToken = driverLogin.body.access_token;
  const otherToken = otherLogin.body.access_token;

  const forbiddenCreate = await request('/api/missions', driverToken, { method: 'POST', body: JSON.stringify({}) });
  assert.equal(forbiddenCreate.status, 403);

  const create = await request('/api/missions', dispatcherToken, { method: 'POST', body: JSON.stringify({
    title: "Livraison test ' OR 1=1 --", destination: 'Entrepôt A', secret_code: 'ZONE-8-SECRET', driver_id: driver.id,
  }) });
  assert.equal(create.status, 201);
  const mission = await create.json();
  const storedCiphertext = db.prepare('SELECT secret_ciphertext FROM missions WHERE id = ?').get(mission.id).secret_ciphertext;
  assert.equal(storedCiphertext.includes('ZONE-8-SECRET'), false);

  const assigned = await (await request('/api/missions', driverToken)).json();
  const unassigned = await (await request('/api/missions', otherToken)).json();
  assert.equal(assigned.length, 1);
  assert.equal(assigned[0].id, mission.id);
  assert.equal(unassigned.length, 0);

  const denied = await request(`/api/missions/${mission.id}/secret/reveal`, otherToken, { method: 'POST' });
  assert.equal(denied.status, 404);
  const reveal = await request(`/api/missions/${mission.id}/secret/reveal`, driverToken, { method: 'POST' });
  assert.equal((await reveal.json()).secret_code, 'ZONE-8-SECRET');

  const invalidTransition = await request(`/api/missions/${mission.id}/status`, driverToken, { method: 'PATCH', body: JSON.stringify({ status: 'COMPLETED' }) });
  assert.equal(invalidTransition.status, 409);
  const start = await request(`/api/missions/${mission.id}/status`, driverToken, { method: 'PATCH', body: JSON.stringify({ status: 'IN_PROGRESS' }) });
  assert.equal(start.status, 200);

  const form = new FormData();
  form.append('file', new Blob([Buffer.from('%PDF-1.7\nsmall test document')], { type: 'application/pdf' }), 'proof.pdf');
  const uploaded = await request(`/api/missions/${mission.id}/documents`, driverToken, { method: 'POST', body: form });
  assert.equal(uploaded.status, 201);
  const proof = await uploaded.json();
  const list = await (await request(`/api/missions/${mission.id}/documents`, dispatcherToken)).json();
  assert.equal(list.length, 1);
  const download = await request(`/api/missions/${mission.id}/documents/${proof.id}`, dispatcherToken);
  assert.equal(download.status, 200);
  assert.match(await download.text(), /^%PDF-1\.7/);

  const auditRows = db.prepare('SELECT action, previous_mac, event_mac FROM audit_log ORDER BY id').all();
  assert.ok(auditRows.some((row) => row.action === 'LOGIN_FAILED'));
  assert.ok(auditRows.some((row) => row.action === 'MISSION_SECRET_REVEALED'));
  assert.ok(auditRows.some((row) => row.action === 'DELIVERY_PROOF_DOWNLOADED'));
  for (let index = 1; index < auditRows.length; index += 1) assert.equal(auditRows[index].previous_mac, auditRows[index - 1].event_mac);
  assert.throws(() => db.prepare('DELETE FROM audit_log').run(), /append-only/);

  await request('/api/auth/logout', dispatcherToken, { method: 'POST' });
  assert.equal((await request('/api/me', dispatcherToken)).status, 401);
});

test('serves the client without embedding credentials or allowing cross-origin access', async () => {
  const response = await fetch(`${origin}/`);
  const html = await response.text();
  assert.equal(response.status, 200);
  assert.match(html, /GML-SHIELD/);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.equal(response.headers.get('content-security-policy')?.includes("script-src 'self'"), true);
});
