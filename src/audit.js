import { auditMac } from './security.js';
import { withTransaction } from './database.js';

/**
 * Le lien avec le MAC précédent aide à détecter les altérations du journal.
 * Ce mécanisme local ne protège pas contre un administrateur possédant la clé
 * et le serveur. Une copie externe avec rétention verrouillée reste nécessaire.
 * Ne pas inclure de mot de passe, de jeton ou de code d'accès dans ces événements.
 */
export function appendAudit(db, auditKey, { userId = null, action, objectType, objectId = null, ipAddress = 'unknown' }) {
  const append = () => {
    const previous = db.prepare('SELECT event_mac FROM audit_log ORDER BY id DESC LIMIT 1').get()?.event_mac ?? 'GENESIS';
    const occurredAt = new Date().toISOString();
    const event = { user_id: userId, action, object_type: objectType, object_id: objectId, ip_address: ipAddress, occurred_at: occurredAt, previous_mac: previous };
    const eventMac = auditMac(auditKey, JSON.stringify(event));
    db.prepare(`INSERT INTO audit_log (user_id, action, object_type, object_id, ip_address, occurred_at, previous_mac, event_mac)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(userId, action, objectType, objectId, ipAddress, occurredAt, previous, eventMac);
    return eventMac;
  };
  return db.isTransaction ? append() : withTransaction(db, append);
}
