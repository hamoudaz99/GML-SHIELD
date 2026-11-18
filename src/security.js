import { createCipheriv, createDecipheriv, createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const SCRYPT_OPTIONS = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

/**
 * Un sel propre à chaque mot de passe évite de partager la même empreinte.
 * scrypt augmente le coût des essais hors ligne. Ne pas remplacer ce mécanisme
 * par un hash rapide, et recalibrer son coût avant un changement de matériel.
 */
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const digest = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
  return `scrypt$32768$8$1$${salt.toString('base64url')}$${digest.toString('base64url')}`;
}

export async function verifyPassword(password, encodedHash) {
  const [scheme, n, r, p, saltText, digestText] = String(encodedHash).split('$');
  if (scheme !== 'scrypt' || n !== '32768' || r !== '8' || p !== '1' || !saltText || !digestText) return false;
  try {
    const salt = Buffer.from(saltText, 'base64url');
    const expected = Buffer.from(digestText, 'base64url');
    const actual = await scrypt(password, salt, expected.length, SCRYPT_OPTIONS);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export function hashSessionToken(token, key) {
  return createHmac('sha256', key).update('gml-shield-session-v1:').update(token).digest('hex');
}

/**
 * Le code d'entrepôt doit être récupérable par le chauffeur autorisé : il est
 * chiffré, contrairement au mot de passe qui est haché. GCM vérifie aussi
 * l'intégrité du contenu. Un nouvel IV est généré à chaque chiffrement.
 * La clé doit rester hors de la base ; sa possession permet le déchiffrement.
 */
export function encryptSecret(plaintext, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ciphertext.toString('base64url')].join('.');
}

export function decryptSecret(value, key) {
  const [version, ivText, tagText, ciphertextText] = String(value).split('.');
  if (version !== 'v1' || !ivText || !tagText || !ciphertextText) throw new Error('Invalid encrypted value');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivText, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextText, 'base64url')), decipher.final()]).toString('utf8');
}

export function auditMac(key, canonicalEvent) {
  return createHmac('sha256', key).update(canonicalEvent).digest('hex');
}
