import { createServer } from 'node:http';
import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, unlinkSync, chmodSync, createReadStream } from 'node:fs';
import { resolve, extname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase, withTransaction } from './database.js';
import { appendAudit } from './audit.js';
import { decryptSecret, encryptSecret, hashSessionToken, verifyPassword } from './security.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const PUBLIC_DIR = resolve(ROOT, 'public');
const MAX_JSON_BYTES = 1024 * 1024;
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const STATUSES = ['PENDING', 'IN_PROGRESS', 'COMPLETED'];
const NEXT_STATUS = { PENDING: 'IN_PROGRESS', IN_PROGRESS: 'COMPLETED' };
const CONTENT_TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const liveDrivers = new Map();
const loginAttempts = new Map();
const DUMMY_HASH = 'scrypt$32768$8$1$MDEyMzQ1Njc4OWFiY2RlZg$' + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function readKeys() {
  const encryptionKey = Buffer.from(process.env.GML_SECRET_KEY_B64 ?? '', 'base64');
  const auditKey = Buffer.from(process.env.GML_AUDIT_KEY_B64 ?? '', 'base64');
  const sessionKey = Buffer.from(process.env.GML_SESSION_KEY_B64 ?? '', 'base64');
  if (encryptionKey.length !== 32) throw new Error('GML_SECRET_KEY_B64 must contain 32 random bytes encoded as base64');
  if (auditKey.length < 32) throw new Error('GML_AUDIT_KEY_B64 must contain at least 32 random bytes encoded as base64');
  if (sessionKey.length < 32) throw new Error('GML_SESSION_KEY_B64 must contain at least 32 random bytes encoded as base64');
  return { encryptionKey, auditKey, sessionKey };
}

function sendJson(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end(body === undefined ? '' : JSON.stringify(body));
}

function sendError(response, status, code, message) {
  sendJson(response, status, { error: code, message });
}

function clientIp(request) {
  // Only trust forwarding headers after an explicitly configured trusted proxy.
  return request.socket.remoteAddress ?? 'unknown';
}

function secureHeaders(response) {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  response.setHeader('Cache-Control', 'no-store');
}

function parseJson(request, maximum = MAX_JSON_BYTES) {
  return new Promise((resolveBody, reject) => {
    let size = 0;
    const chunks = [];
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > maximum) {
        reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      try { resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(Object.assign(new Error('Invalid JSON body'), { statusCode: 400 })); }
    });
    request.on('error', reject);
  });
}

function parseMultipartFile(request) {
  return new Promise((resolveFile, reject) => {
    const contentType = request.headers['content-type'] ?? '';
    const boundary = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType)?.slice(1).find(Boolean)?.trim();
    if (!contentType.toLowerCase().startsWith('multipart/form-data') || !boundary || boundary.length > 200) {
      reject(Object.assign(new Error('Expected multipart/form-data'), { statusCode: 415 }));
      return;
    }
    let size = 0;
    const chunks = [];
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_UPLOAD_BYTES + 64 * 1024) {
        reject(Object.assign(new Error('Upload exceeds 10 MiB'), { statusCode: 413 }));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      try {
        const body = Buffer.concat(chunks);
        const delimiter = Buffer.from(`--${boundary}`);
        const parts = [];
        let cursor = body.indexOf(delimiter) + delimiter.length;
        while (cursor >= delimiter.length) {
          if (body.subarray(cursor, cursor + 2).equals(Buffer.from('--'))) break;
          if (body.subarray(cursor, cursor + 2).equals(Buffer.from('\r\n'))) cursor += 2;
          const next = body.indexOf(delimiter, cursor);
          if (next < 0) break;
          let part = body.subarray(cursor, next);
          if (part.subarray(-2).equals(Buffer.from('\r\n'))) part = part.subarray(0, -2);
          const divider = part.indexOf(Buffer.from('\r\n\r\n'));
          if (divider >= 0) parts.push({ headers: part.subarray(0, divider).toString('utf8'), data: part.subarray(divider + 4) });
          cursor = next + delimiter.length;
        }
        const candidate = parts.find((part) => /filename="/i.test(part.headers));
        if (!candidate || parts.filter((part) => /filename="/i.test(part.headers)).length !== 1) throw Object.assign(new Error('Upload exactly one file'), { statusCode: 400 });
        const fileName = /filename="([^"]*)"/i.exec(candidate.headers)?.[1] ?? 'proof';
        const mimeType = /content-type:\s*([^\r\n]+)/i.exec(candidate.headers)?.[1]?.trim().toLowerCase() ?? '';
        if (!candidate.data.length || candidate.data.length > MAX_UPLOAD_BYTES) throw Object.assign(new Error('File must be between 1 byte and 10 MiB'), { statusCode: 413 });
        resolveFile({ fileName, mimeType, data: candidate.data });
      } catch (error) { reject(error); }
    });
    request.on('error', reject);
  });
}

function fileMatchesMime(data, mimeType) {
  if (mimeType === 'application/pdf') return data.subarray(0, 5).toString('ascii') === '%PDF-';
  if (mimeType === 'image/jpeg') return data[0] === 0xff && data[1] === 0xd8 && data.at(-2) === 0xff && data.at(-1) === 0xd9;
  if (mimeType === 'image/png') return data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  return false;
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * La session côté serveur permet une révocation immédiate sur les requêtes.
 * On conserve seulement l'empreinte du jeton pour limiter l'effet d'une fuite
 * de la table sessions. Ne jamais faire confiance au rôle envoyé par le client.
 */
function authorized(request, db, sessionKey) {
  const token = /^Bearer ([A-Za-z0-9_-]{32,})$/.exec(request.headers.authorization ?? '')?.[1];
  if (!token) return null;
  const session = db.prepare(`SELECT users.id, users.email, users.role, users.is_active
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?`).get(hashSessionToken(token, sessionKey), Date.now());
  if (!session || !session.is_active) return null;
  return { id: session.id, email: session.email, role: session.role, tokenHash: hashSessionToken(token, sessionKey) };
}

function audit(db, auditKey, request, user, action, objectType, objectId = null) {
  return appendAudit(db, auditKey, { userId: user?.id ?? null, action, objectType, objectId, ipAddress: clientIp(request) });
}

/**
 * L'identifiant de mission ne suffit pas à autoriser l'accès : la requête doit
 * aussi vérifier son lien avec l'utilisateur authentifié. Les paramètres SQL
 * séparent les valeurs reçues de la structure de la requête.
 * Lors d'une ouverture partenaire, ajouter une isolation par tenant vérifiée.
 */
function getMissionForUser(db, missionId, user) {
  if (user.role === 'DRIVER') return db.prepare('SELECT * FROM missions WHERE id = ? AND driver_id = ?').get(missionId, user.id);
  if (user.role === 'DISPATCHER') return db.prepare('SELECT * FROM missions WHERE id = ? AND dispatcher_id = ?').get(missionId, user.id);
  return undefined;
}

/** 
 * Construit la réponse destinée au client avec les champs explicitement choisis.
 * Cela évite d'exposer automatiquement les colonnes internes de la base.
 * Le code d'accès reste absent par défaut ; includeSecret permet sa révélation.
 * L'appelant doit vérifier les droits avant d'activer cette option :
 * cette fonction ne réalise pas elle-même le contrôle d'accès.
 */

function publicMission(row, includeSecret = false, encryptionKey = null) {
  return {
    id: row.id, title: row.title, destination: row.destination, status: row.status,
    driver_id: row.driver_id, dispatcher_id: row.dispatcher_id, created_at: row.created_at,
    ...(includeSecret ? { secret_code: decryptSecret(row.secret_ciphertext, encryptionKey) } : {}),
  };
}

function createHandler({ db, encryptionKey, auditKey, sessionKey, uploadDir, sessionTtlMs }) {
  mkdirSync(uploadDir, { recursive: true, mode: 0o700 });
  chmodSync(uploadDir, 0o700);

  return async function handle(request, response) {
    secureHeaders(response);
    const url = new URL(request.url, 'http://localhost');
    const path = url.pathname;
    const method = request.method ?? 'GET';
    const ip = clientIp(request);

    try {
      if (method === 'GET' && (path === '/' || path === '/index.html' || path === '/app.js' || path === '/style.css')) {
        const file = path === '/' || path === '/index.html' ? 'index.html' : path.slice(1);
        const body = readFileSync(resolve(PUBLIC_DIR, file));
        response.writeHead(200, { 'Content-Type': CONTENT_TYPES[extname(file)] ?? 'application/octet-stream' });
        response.end(body);
        return;
      }
      if (method === 'GET' && path === '/healthz') { sendJson(response, 200, { status: 'ok' }); return; }

      if (method === 'POST' && path === '/api/auth/login') {
        const attempts = loginAttempts.get(ip) ?? { count: 0, started: Date.now() };
        if (Date.now() - attempts.started > 60_000) { attempts.count = 0; attempts.started = Date.now(); }
        attempts.count += 1; loginAttempts.set(ip, attempts);
        if (attempts.count > 10) { sendError(response, 429, 'rate_limited', 'Réessayez dans une minute.'); return; }
        const body = await parseJson(request);
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        const record = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
        const valid = await verifyPassword(password, record?.password_hash ?? DUMMY_HASH);
        if (!record || !record.is_active || !valid) {
          audit(db, auditKey, request, null, 'LOGIN_FAILED', 'user', null);
          sendError(response, 401, 'invalid_credentials', 'Identifiants invalides.'); return;
        }
        loginAttempts.delete(ip);
        const token = randomBytes(32).toString('base64url');
        const expiresAt = Date.now() + sessionTtlMs;
        withTransaction(db, () => {
          db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
          db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)')
            .run(hashSessionToken(token, sessionKey), record.id, expiresAt, new Date().toISOString());
        });
        audit(db, auditKey, request, { id: record.id }, 'LOGIN_SUCCEEDED', 'user', record.id);
        sendJson(response, 200, { access_token: token, token_type: 'Bearer', expires_in: Math.floor(sessionTtlMs / 1000), user: { id: record.id, email: record.email, role: record.role } });
        return;
      }

      const user = authorized(request, db, sessionKey);
      if (path.startsWith('/api/') && !user) { sendError(response, 401, 'unauthorized', 'Connexion requise.'); return; }

      if (method === 'POST' && path === '/api/auth/logout') {
        withTransaction(db, () => db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(user.tokenHash));
        audit(db, auditKey, request, user, 'LOGOUT', 'user', user.id);
        sendJson(response, 204); return;
      }
      if (method === 'GET' && path === '/api/me') { sendJson(response, 200, { id: user.id, email: user.email, role: user.role }); return; }

      if (method === 'GET' && path === '/api/events') {
        if (user.role !== 'DRIVER') { sendError(response, 403, 'forbidden', 'Réservé au chauffeur.'); return; }
        response.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
        response.write(': connected\n\n');
        const bucket = liveDrivers.get(user.id) ?? new Set(); bucket.add(response); liveDrivers.set(user.id, bucket);
        const heartbeat = setInterval(() => { if (!response.destroyed) response.write(': keepalive\n\n'); }, 25_000);
        request.on('close', () => { clearInterval(heartbeat); bucket.delete(response); if (bucket.size === 0) liveDrivers.delete(user.id); });
        return;
      }

      if (method === 'POST' && path === '/api/missions') {
        if (user.role !== 'DISPATCHER') { sendError(response, 403, 'forbidden', 'Réservé au répartiteur.'); return; }
        const body = await parseJson(request);
        const title = typeof body.title === 'string' ? body.title.trim() : '';
        const destination = typeof body.destination === 'string' ? body.destination.trim() : '';
        const secretCode = typeof body.secret_code === 'string' ? body.secret_code.trim() : '';
        const driverId = typeof body.driver_id === 'string' ? body.driver_id : '';
        if (!title || title.length > 120 || !destination || destination.length > 300 || !secretCode || secretCode.length > 200 || !driverId) {
          sendError(response, 400, 'invalid_mission', 'Vérifiez le titre, la destination, le code et le chauffeur.'); return;
        }
        const driver = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'DRIVER' AND is_active = 1").get(driverId);
        if (!driver) { sendError(response, 400, 'invalid_driver', 'Chauffeur inconnu ou inactif.'); return; }
        const missionId = randomUUID(); const now = new Date().toISOString();
        withTransaction(db, () => {
          db.prepare(`INSERT INTO missions (id,title,destination,secret_ciphertext,status,driver_id,dispatcher_id,created_at,updated_at)
            VALUES (?, ?, ?, ?, 'PENDING', ?, ?, ?, ?)`).run(missionId, title, destination, encryptSecret(secretCode, encryptionKey), driverId, user.id, now, now);
          appendAudit(db, auditKey, { userId: user.id, action: 'MISSION_CREATED', objectType: 'mission', objectId: missionId, ipAddress: ip });
        });
        for (const stream of liveDrivers.get(driverId) ?? []) stream.write(`event: NEW_MISSION\ndata: ${JSON.stringify({ mission_id: missionId })}\n\n`);
        sendJson(response, 201, { id: missionId, title, destination, status: 'PENDING', driver_id: driverId, dispatcher_id: user.id, created_at: now });
        return;
      }

      if (method === 'GET' && path === '/api/drivers') {
        if (user.role !== 'DISPATCHER') { sendError(response, 403, 'forbidden', 'Réservé au répartiteur.'); return; }
        const drivers = db.prepare("SELECT id, email FROM users WHERE role = 'DRIVER' AND is_active = 1 ORDER BY email").all();
        sendJson(response, 200, drivers); return;
      }

      if (method === 'GET' && path === '/api/missions') {
        let rows;
        if (user.role === 'DISPATCHER') rows = db.prepare('SELECT * FROM missions WHERE dispatcher_id = ? ORDER BY created_at DESC').all(user.id);
        else if (user.role === 'DRIVER') rows = db.prepare('SELECT * FROM missions WHERE driver_id = ? ORDER BY created_at DESC').all(user.id);
        else { sendError(response, 403, 'forbidden', 'Aucune mission disponible pour ce rôle.'); return; }
        audit(db, auditKey, request, user, 'MISSION_LIST_VIEWED', 'mission_collection');
        sendJson(response, 200, rows.map((row) => publicMission(row))); return;
      }

      const secretRoute = /^\/api\/missions\/([0-9a-f-]{36})\/secret\/reveal$/.exec(path);
      if (method === 'POST' && secretRoute) {
        const mission = getMissionForUser(db, secretRoute[1], user);
        if (!mission || user.role !== 'DRIVER') { sendError(response, 404, 'not_found', 'Mission introuvable.'); return; }
        audit(db, auditKey, request, user, 'MISSION_SECRET_REVEALED', 'mission', mission.id);
        sendJson(response, 200, { secret_code: decryptSecret(mission.secret_ciphertext, encryptionKey) }); return;
      }

      const statusRoute = /^\/api\/missions\/([0-9a-f-]{36})\/status$/.exec(path);
      if (method === 'PATCH' && statusRoute) {
        if (user.role !== 'DRIVER') { sendError(response, 403, 'forbidden', 'Réservé au chauffeur.'); return; }
        const mission = getMissionForUser(db, statusRoute[1], user);
        if (!mission) { sendError(response, 404, 'not_found', 'Mission introuvable.'); return; }
        const body = await parseJson(request);
        if (body.status !== NEXT_STATUS[mission.status] || !STATUSES.includes(body.status)) { sendError(response, 409, 'invalid_transition', 'Le statut demandé ne suit pas le cycle autorisé.'); return; }
        const now = new Date().toISOString();
        withTransaction(db, () => {
          db.prepare('UPDATE missions SET status = ?, updated_at = ? WHERE id = ? AND driver_id = ?').run(body.status, now, mission.id, user.id);
          appendAudit(db, auditKey, { userId: user.id, action: 'MISSION_STATUS_CHANGED', objectType: 'mission', objectId: mission.id, ipAddress: ip });
        });
        sendJson(response, 200, { id: mission.id, status: body.status, updated_at: now }); return;
      }

      const uploadRoute = /^\/api\/missions\/([0-9a-f-]{36})\/documents$/.exec(path);
      if (method === 'POST' && uploadRoute) {
        if (user.role !== 'DRIVER') { sendError(response, 403, 'forbidden', 'Réservé au chauffeur assigné.'); return; }
        const mission = getMissionForUser(db, uploadRoute[1], user);
        if (!mission || mission.status !== 'IN_PROGRESS') { sendError(response, 404, 'not_found', 'Mission en cours introuvable.'); return; }
        const file = await parseMultipartFile(request);
        if (!fileMatchesMime(file.data, file.mimeType)) { sendError(response, 415, 'unsupported_file', 'Formats autorisés : PDF, JPEG ou PNG avec signature vérifiée.'); return; }
        const documentId = randomUUID(); const storageKey = randomUUID(); const extension = { 'application/pdf': '.pdf', 'image/jpeg': '.jpg', 'image/png': '.png' }[file.mimeType];
        const storagePath = resolve(uploadDir, storageKey + extension);
        writeFileSync(storagePath, file.data, { flag: 'wx', mode: 0o600 });
        const now = new Date().toISOString(); const digest = createHash('sha256').update(file.data).digest('hex');
        try {
          withTransaction(db, () => {
            db.prepare(`INSERT INTO documents (id,mission_id,storage_key,original_name,mime_type,byte_size,sha256,uploaded_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(documentId, mission.id, storageKey + extension, basename(file.fileName).slice(0, 180), file.mimeType, file.data.length, digest, now);
            appendAudit(db, auditKey, { userId: user.id, action: 'DELIVERY_PROOF_UPLOADED', objectType: 'document', objectId: documentId, ipAddress: ip });
          });
        } catch (error) { unlinkSync(storagePath); throw error; }
        sendJson(response, 201, { id: documentId, mission_id: mission.id, mime_type: file.mimeType, byte_size: file.data.length, uploaded_at: now }); return;
      }

      const documentsRoute = /^\/api\/missions\/([0-9a-f-]{36})\/documents$/.exec(path);
      if (method === 'GET' && documentsRoute) {
        const mission = getMissionForUser(db, documentsRoute[1], user);
        if (!mission || !['DISPATCHER', 'DRIVER'].includes(user.role)) { sendError(response, 404, 'not_found', 'Mission introuvable.'); return; }
        const rows = db.prepare('SELECT id,mime_type,byte_size,uploaded_at FROM documents WHERE mission_id = ? ORDER BY uploaded_at DESC').all(mission.id);
        audit(db, auditKey, request, user, 'DELIVERY_PROOF_LIST_VIEWED', 'mission', mission.id);
        sendJson(response, 200, rows); return;
      }

      const documentRoute = /^\/api\/missions\/([0-9a-f-]{36})\/documents\/([0-9a-f-]{36})$/.exec(path);
      if (method === 'GET' && documentRoute) {
        const mission = getMissionForUser(db, documentRoute[1], user);
        const document = mission ? db.prepare('SELECT * FROM documents WHERE id = ? AND mission_id = ?').get(documentRoute[2], mission.id) : null;
        if (!document || !['DISPATCHER', 'DRIVER'].includes(user.role)) { sendError(response, 404, 'not_found', 'Document introuvable.'); return; }
        audit(db, auditKey, request, user, 'DELIVERY_PROOF_DOWNLOADED', 'document', document.id);
        response.writeHead(200, { 'Content-Type': document.mime_type, 'Content-Length': document.byte_size, 'Content-Disposition': `attachment; filename="${document.id}${extname(document.storage_key)}"`, 'X-Content-Type-Options': 'nosniff' });
        createReadStream(resolve(uploadDir, document.storage_key)).pipe(response); return;
      }

      if (method === 'GET' && path === '/api/admin/audit') {
        if (user.role !== 'ADMIN') { sendError(response, 403, 'forbidden', 'Réservé à l’admin sécurité.'); return; }
        const rows = db.prepare(`SELECT id,user_id,action,object_type,object_id,ip_address,occurred_at,previous_mac,event_mac
          FROM audit_log ORDER BY id DESC LIMIT 500`).all();
        sendJson(response, 200, rows); return;
      }

      sendError(response, 404, 'not_found', 'Ressource introuvable.');
    } catch (error) {
      if (!response.headersSent) sendError(response, error.statusCode ?? 500, error.statusCode === 413 ? 'payload_too_large' : 'request_failed', error.statusCode && error.statusCode < 500 ? error.message : 'Une erreur est survenue.');
      else response.destroy();
    }
  };
}

export function startServer({ port = Number(process.env.PORT ?? 8080), host = process.env.HOST ?? '127.0.0.1', databasePath = process.env.DATABASE_PATH ?? './data/gml-shield.sqlite', uploadDir = process.env.UPLOAD_DIR ?? './var/private-uploads', sessionTtlMs = Number(process.env.SESSION_TTL_SECONDS ?? 900) * 1000 } = {}) {
  const { encryptionKey, auditKey, sessionKey } = readKeys();
  const db = openDatabase(databasePath);
  const server = createServer(createHandler({ db, encryptionKey, auditKey, sessionKey, uploadDir: resolve(uploadDir), sessionTtlMs }));
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.listen(port, host, () => console.log(`GML-SHIELD listening on http://${host}:${server.address().port}`));
  return { server, db };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) startServer();
