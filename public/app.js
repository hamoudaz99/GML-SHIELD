const loginPanel = document.querySelector('#login-panel');
const appPanel = document.querySelector('#app-panel');
const loginError = document.querySelector('#login-error');
const missionList = document.querySelector('#mission-list');
const notice = document.querySelector('#notice');
let accessToken = null;
let currentUser = null;
let eventAbortController = null;

/**
 * Le jeton reste en mémoire pour éviter sa persistance dans le navigateur.
 * Cela n'élimine pas le risque XSS pendant une session active. Les permissions
 * restent vérifiées par le serveur, même si l'interface masque certains boutons.
 */
async function api(path, options = {}) {
  const headers = new Headers(options.headers ?? {});
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...options, headers, credentials: 'omit', cache: 'no-store' });
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.message ?? 'La demande n’a pas abouti.');
    error.status = response.status;
    throw error;
  }
  return payload;
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showNotice(message) {
  notice.textContent = message;
  notice.hidden = false;
  window.setTimeout(() => { notice.hidden = true; }, 5000);
}

function showSignedIn(user) {
  currentUser = user;
  loginPanel.hidden = true;
  appPanel.hidden = false;
  document.querySelector('#session-area').hidden = false;
  document.querySelector('#session-label').textContent = user.email;
  document.querySelector('#role-label').textContent = user.role;
  document.querySelector('#dispatcher-panel').hidden = user.role !== 'DISPATCHER';
  document.querySelector('#admin-panel').hidden = user.role !== 'ADMIN';
  document.querySelector('#page-title').textContent = user.role === 'DISPATCHER' ? 'Suivi des tournées' : 'Mes missions';
  document.querySelector('#list-title').textContent = user.role === 'DISPATCHER' ? 'Missions créées' : 'Missions assignées';
}

function statusLabel(status) {
  return { PENDING: 'En attente', IN_PROGRESS: 'En cours', COMPLETED: 'Terminée' }[status] ?? status;
}

async function downloadDocument(missionId, documentId) {
  const headers = new Headers({ Authorization: `Bearer ${accessToken}` });
  const response = await fetch(`/api/missions/${missionId}/documents/${documentId}`, { headers, cache: 'no-store' });
  if (!response.ok) throw new Error('Téléchargement indisponible.');
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = element('a'); link.href = objectUrl; link.download = `${documentId}`; link.click();
  URL.revokeObjectURL(objectUrl);
}

async function addDocuments(card, mission) {
  const documents = await api(`/api/missions/${mission.id}/documents`);
  for (const documentInfo of documents) {
    const button = element('button', 'secondary', `Télécharger la preuve (${documentInfo.mime_type})`);
    button.type = 'button';
    button.addEventListener('click', async () => {
      try { await downloadDocument(mission.id, documentInfo.id); }
      catch (error) { showNotice(error.message); }
    });
    card.querySelector('.actions').append(button);
  }
}

function missionCard(mission) {
  const card = element('article', 'mission-card');
  const head = element('div', 'mission-head');
  const info = element('div');
  info.append(element('h4', '', mission.title));
  info.append(element('p', 'mission-meta', `Destination : ${mission.destination}`));
  const status = element('span', 'status', statusLabel(mission.status));
  head.append(info, status); card.append(head);
  const actions = element('div', 'actions'); actions.className = 'actions'; card.append(actions);

  if (currentUser.role === 'DRIVER') {
    if (mission.status === 'PENDING' || mission.status === 'IN_PROGRESS') {
      const statusButton = element('button', 'secondary', mission.status === 'PENDING' ? 'Démarrer la mission' : 'Clôturer la mission');
      statusButton.type = 'button';
      statusButton.addEventListener('click', async () => {
        try {
          const nextStatus = mission.status === 'PENDING' ? 'IN_PROGRESS' : 'COMPLETED';
          await api(`/api/missions/${mission.id}/status`, { method: 'PATCH', body: JSON.stringify({ status: nextStatus }) });
          await refreshMissions();
        } catch (error) { showNotice(error.message); }
      });
      actions.append(statusButton);
    }
    const revealButton = element('button', 'secondary', 'Révéler le code d’accès'); revealButton.type = 'button';
    revealButton.addEventListener('click', async () => {
      try {
        const result = await api(`/api/missions/${mission.id}/secret/reveal`, { method: 'POST' });
        const old = card.querySelector('.secret'); if (old) old.remove();
        card.insertBefore(element('p', 'secret', `Code d’accès : ${result.secret_code}`), actions);
      } catch (error) { showNotice(error.message); }
    });
    actions.append(revealButton);
    if (mission.status === 'IN_PROGRESS') {
      const upload = element('form', 'actions');
      const file = element('input'); file.type = 'file'; file.accept = '.pdf,.jpg,.jpeg,.png'; file.required = true; file.setAttribute('aria-label', 'Preuve de livraison PDF ou image');
      const submit = element('button', 'secondary', 'Envoyer une preuve'); submit.type = 'submit';
      upload.append(file, submit);
      upload.addEventListener('submit', async (event) => {
        event.preventDefault();
        const data = new FormData(); data.append('file', file.files[0]);
        try { await api(`/api/missions/${mission.id}/documents`, { method: 'POST', body: data }); showNotice('Preuve enregistrée.'); await refreshMissions(); }
        catch (error) { showNotice(error.message); }
      });
      card.append(upload);
    }
    addDocuments(card, mission).catch(() => {});
  }
  if (currentUser.role === 'DISPATCHER') addDocuments(card, mission).catch(() => {});
  return card;
}

async function refreshMissions() {
  try {
    const missions = await api('/api/missions');
    missionList.replaceChildren();
    if (!missions.length) { missionList.append(element('p', 'muted', 'Aucune mission à afficher.')); return; }
    for (const mission of missions) missionList.append(missionCard(mission));
  } catch (error) {
    if (error.status === 401) await signOut(false);
    else showNotice(error.message);
  }
}

async function loadDrivers() {
  if (currentUser.role !== 'DISPATCHER') return;
  const list = await api('/api/drivers');
  const select = document.querySelector('#mission-form select[name="driver_id"]');
  select.replaceChildren();
  for (const driver of list) {
    const option = element('option', '', driver.email); option.value = driver.id; select.append(option);
  }
}

async function loadAudit() {
  if (currentUser.role !== 'ADMIN') return;
  const rows = await api('/api/admin/audit');
  const container = document.querySelector('#audit-list'); container.replaceChildren();
  for (const row of rows) {
    const item = element('div', 'audit-row');
    item.append(element('span', '', row.occurred_at), element('strong', '', row.action), element('span', '', `${row.object_type} ${row.object_id ?? ''}`));
    container.append(item);
  }
}

async function connectEvents() {
  if (currentUser.role !== 'DRIVER') return;
  eventAbortController?.abort(); eventAbortController = new AbortController();
  try {
    const response = await fetch('/api/events', { headers: { Authorization: `Bearer ${accessToken}` }, signal: eventAbortController.signal, cache: 'no-store' });
    if (!response.ok || !response.body) throw new Error('Flux de notifications indisponible.');
    const reader = response.body.getReader(); const decoder = new TextDecoder(); let pending = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      pending += decoder.decode(value, { stream: true });
      const events = pending.split('\n\n'); pending = events.pop() ?? '';
      for (const block of events) if (block.includes('event: NEW_MISSION')) { showNotice('Une nouvelle mission vous a été assignée.'); await refreshMissions(); }
    }
  } catch (error) {
    if (error.name !== 'AbortError' && accessToken) window.setTimeout(connectEvents, 3000);
  }
}

async function signOut(callServer = true) {
  eventAbortController?.abort();
  if (callServer && accessToken) { try { await api('/api/auth/logout', { method: 'POST' }); } catch {} }
  accessToken = null; currentUser = null;
  document.querySelector('#session-area').hidden = true;
  appPanel.hidden = true; loginPanel.hidden = false;
}

document.querySelector('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); loginError.textContent = '';
  const data = new FormData(event.currentTarget);
  try {
    const result = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email: data.get('email'), password: data.get('password') }) });
    accessToken = result.access_token; showSignedIn(result.user); await loadDrivers(); await refreshMissions(); await loadAudit(); connectEvents();
  } catch (error) { loginError.textContent = error.message; }
});

document.querySelector('#mission-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const data = new FormData(event.currentTarget);
  try {
    await api('/api/missions', { method: 'POST', body: JSON.stringify({ title: data.get('title'), destination: data.get('destination'), driver_id: data.get('driver_id'), secret_code: data.get('secret_code') }) });
    event.currentTarget.reset(); await refreshMissions(); showNotice('Mission créée et envoyée au chauffeur.');
  } catch (error) { showNotice(error.message); }
});

document.querySelector('#logout-button').addEventListener('click', () => signOut());
document.querySelector('#refresh-button').addEventListener('click', refreshMissions);
