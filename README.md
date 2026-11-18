# GML-SHIELD — MVP interne

MVP de démonstration pour le cas d’examen. Le serveur REST et l’interface web sont dans le même processus Node.js. L’MVP couvre la connexion, les missions répartiteur/chauffeur, la révélation contrôlée du code d’accès, le suivi du statut, les notifications SSE, les preuves de livraison et une trace d’audit signée.

Cette version est limitée à une organisation interne GML. Elle ne fournit pas encore la séparation multi-tenant ni l’archivage immuable externalisé requis pour ouvrir le service à des partenaires et prétendre à une conservation réglementaire de six mois. Le fichier SQLite et sa chaîne HMAC rendent les modifications ordinaires détectables, mais un administrateur du serveur ou une compromission de ses secrets restent hors de la garantie d’un stockage WORM. Ne pas mettre en production avec des données de transport réelles sans les mesures de production du DAT.

## Pré-requis et démarrage local

- Node.js 24.9 ou plus récent, pour `node:sqlite`.
- Un poste de démonstration ; aucun paquet npm externe n’est utilisé.

Depuis ce dossier, générer trois clés indépendantes et les injecter dans l’environnement du processus. Les commandes ci-dessous affichent des secrets : les conserver dans un gestionnaire sécurisé et ne jamais les committer.

```bash
export GML_SECRET_KEY_B64="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64'))")"
export GML_AUDIT_KEY_B64="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64'))")"
export GML_SESSION_KEY_B64="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64'))")"
npm start
```

Dans un second terminal, créer les utilisateurs de test. Le mot de passe est lu depuis l’entrée standard, il n’est pas passé comme argument de ligne de commande.

```bash
npm run create-user -- repartiteur@gml.test DISPATCHER
npm run create-user -- chauffeur@gml.test DRIVER
npm run create-user -- securite@gml.test ADMIN
```

Ouvrir `http://127.0.0.1:8080`. Le serveur écoute seulement sur l’adresse locale par défaut. En production, terminer TLS sur un reverse proxy géré, puis configurer le service privé pour n’accepter que ce proxy. Ne pas exposer le port Node directement sur Internet.

## Vérifications

```bash
npm test
```

Les tests vérifient l’authentification, le cloisonnement par chauffeur assigné, les transitions d’état, l’absence de secret en clair dans la base, l’upload/téléchargement d’une preuve, la chaîne des traces et la révocation de session.

## Limites connues et suite nécessaire

- SQLite est utilisé pour rendre le MVP facile à lancer. La cible de production est PostgreSQL avec migrations, sauvegarde/restauration éprouvée, chiffrement de disque, contrôles d’accès et RLS comme défense complémentaire.
- Une authentification locale par jeton opaque court est fournie pour la démonstration. La fédération des partenaires doit passer par un fournisseur OIDC/OAuth 2.0 géré, avec PKCE pour les applications utilisateur ou client credentials pour les échanges serveur à serveur.
- Le journal est append-only dans le processus et chaîné par HMAC. Pour garantir l’inaltérabilité face à un administrateur compromis et six mois de conservation, expédier chaque événement vers un compte de stockage distinct avec verrouillage WORM, alertes d’intégrité, sauvegarde et contrôle de rétention.
- Les pièces jointes sont privées et leur signature de fichier est vérifiée. Ajouter un antivirus en quarantaine, des quotas par chauffeur, une analyse des documents et des tests de restauration avant utilisation réelle.
- La limite d’essais de connexion est locale au processus. La production doit appliquer la limitation au niveau de la passerelle, la supervision centralisée, le MFA des rôles sensibles, la rotation des clés via KMS/HSM et une revue indépendante.
- Le guide de qualité et le DAT annexés décrivent les gates, la cible de production, le cloisonnement multi-tenant, le plan de déploiement progressif et les décisions à valider avec GML.

## Organisation du code

- `src/server.js` — routes HTTP, contrôle d’accès et flux SSE.
- `src/database.js` — schéma local et transactions.
- `src/security.js` — hachage scrypt, jetons, chiffrement AES-256-GCM.
- `src/audit.js` — chaîne HMAC des évènements sensibles.
- `src/create-user.js` — provisionnement interactif des comptes de test.
- `public/` — client web sans dépendances ni stockage persistant du jeton.
- `test/security.test.js` — tests d’intégration exécutés avec le test runner Node.
