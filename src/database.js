import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export function openDatabase(path = process.env.DATABASE_PATH ?? './data/gml-shield.sqlite') {
  const absolutePath = resolve(path);
  mkdirSync(dirname(absolutePath), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(absolutePath);
  chmodSync(absolutePath, 0o600);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('ADMIN', 'DISPATCHER', 'DRIVER')),
      is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS missions (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      destination TEXT NOT NULL,
      secret_ciphertext TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED')),
      driver_id TEXT NOT NULL REFERENCES users(id),
      dispatcher_id TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_missions_driver ON missions(driver_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_missions_dispatcher ON missions(dispatcher_id, created_at);
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
      storage_key TEXT NOT NULL UNIQUE,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      byte_size INTEGER NOT NULL,
      sha256 TEXT NOT NULL,
      uploaded_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT REFERENCES users(id),
      action TEXT NOT NULL,
      object_type TEXT NOT NULL,
      object_id TEXT,
      ip_address TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      previous_mac TEXT NOT NULL,
      event_mac TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
  `);
  return db;
}

/**
 * Les écritures d'une opération doivent réussir ensemble ou être annulées.
 * Le callback est synchrone : ne pas y placer d'appel réseau ni de Promise,
 * sinon COMMIT pourrait survenir avant la fin du travail attendu.
 */
export function withTransaction(db, callback) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const value = callback();
    db.exec('COMMIT');
    return value;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}
