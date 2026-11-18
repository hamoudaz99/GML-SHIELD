import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { openDatabase, withTransaction } from './database.js';
import { hashPassword } from './security.js';

const email = (process.argv[2] ?? '').trim().toLowerCase();
const role = (process.argv[3] ?? '').trim().toUpperCase();
if (!/^\S+@\S+\.\S+$/.test(email) || !['ADMIN', 'DISPATCHER', 'DRIVER'].includes(role)) {
  console.error('Usage: npm run create-user -- person@example.com ADMIN|DISPATCHER|DRIVER');
  process.exit(2);
}

const prompt = createInterface({ input: stdin, output: stdout });
try {
  const password = await prompt.question('Temporary password (12+ characters): ');
  if (password.length < 12) throw new Error('Use a password of at least 12 characters.');
  const db = openDatabase();
  const id = randomUUID();
  const passwordHash = await hashPassword(password);
  withTransaction(db, () => db.prepare('INSERT INTO users (id,email,password_hash,role,is_active,created_at) VALUES (?, ?, ?, ?, 1, ?)')
    .run(id, email, passwordHash, role, new Date().toISOString()));
  console.log(`Created ${role.toLowerCase()} user ${email} (${id}).`);
  db.close();
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  prompt.close();
}
