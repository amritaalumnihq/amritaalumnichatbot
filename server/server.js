const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Allow dashboard to call API from browser
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const DB_PATH   = path.join(__dirname, 'alumni_db.json');
const CONV_PATH = path.join(__dirname, 'conversations.json');

// Init empty files if they don't exist (first deploy)
if (!fs.existsSync(DB_PATH))   fs.writeFileSync(DB_PATH,   '[]',  'utf8');
if (!fs.existsSync(CONV_PATH)) fs.writeFileSync(CONV_PATH, '{}',  'utf8');

// Private key: read from env var (production) or file (local dev)
const PRIVATE_KEY = process.env.PRIVATE_KEY
  ? process.env.PRIVATE_KEY.replace(/\\n/g, '\n')
  : fs.readFileSync(path.join(__dirname, 'private.pem'), 'utf8');

const VERIFY_TOKEN    = process.env.VERIFY_TOKEN    || 'amrita_verify_2024';
const WA_TOKEN        = process.env.WA_TOKEN        || '';
const PHONE_NUMBER_ID = process.env.PHONE_NUMBER_ID || '1181292345065359';
const FLOW_ID         = process.env.FLOW_ID         || '1571206234422583';
const FLOW_MODE       = process.env.FLOW_MODE       || 'published';

function loadDb() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}
function loadConvs() {
  try { return JSON.parse(fs.readFileSync(CONV_PATH, 'utf8')); } catch { return {}; }
}
function saveConvs(c) {
  fs.writeFileSync(CONV_PATH, JSON.stringify(c, null, 2));
}
function addMessage(phone, from, text, type = 'text') {
  const convs = loadConvs();
  if (!convs[phone]) {
    const alumni = findAlumni(phone);
    convs[phone] = { phone, name: alumni?.name || phone, handoff: false, messages: [] };
  }
  convs[phone].messages.push({ from, text, type, ts: new Date().toISOString() });
  convs[phone].lastMessage = text;
  convs[phone].lastTs = new Date().toISOString();
  saveConvs(convs);
}

function normalizePhone(phone) {
  return String(phone).replace(/[\s+\-()]/g, '');
}

function findAlumni(phone) {
  const db = loadDb();
  const p = normalizePhone(phone);
  return db.find(a => {
    const ap = normalizePhone(a.phone);
    return ap === p || ap === '91' + p || p === '91' + ap;
  });
}

function upsertAlumni(phone, fields) {
  const db = loadDb();
  const p = normalizePhone(phone);
  const idx = db.findIndex(a => {
    const ap = normalizePhone(a.phone);
    return ap === p || ap === '91' + p || p === '91' + ap;
  });
  const timestamp = new Date().toISOString();
  if (idx !== -1) {
    db[idx] = { ...db[idx], ...fields, status: 'Updated', lastUpdated: timestamp };
  } else {
    db.push({ phone: p, ...fields, status: 'New', lastUpdated: timestamp });
  }
  saveDb(db);
}

function decryptRequest(body) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;
  const aesKey = crypto.privateDecrypt(
    { key: PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(encrypted_aes_key, 'base64')
  );
  const flowBuf = Buffer.from(encrypted_flow_data, 'base64');
  const iv = Buffer.from(initial_vector, 'base64');
  const TAG_LEN = 16;
  const ciphertext = flowBuf.subarray(0, -TAG_LEN);
  const authTag = flowBuf.subarray(-TAG_LEN);
  const algo = aesKey.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const decipher = crypto.createDecipheriv(algo, aesKey, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return { body: JSON.parse(decrypted.toString()), aesKey, iv, algo };
}

function encryptResponse(data, aesKey, iv, algo) {
  const flippedIv = Buffer.from(iv.map(b => b ^ 0xff));
  const cipher = crypto.createCipheriv(algo, aesKey, flippedIv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), 'utf8'),
    cipher.final(),
    cipher.getAuthTag()
  ]);
  return encrypted.toString('base64');
}

async function sendFlowToPhone(phone) {
  const { default: fetch } = await import('node-fetch').catch(() => ({ default: null }));
  const fetchFn = fetch || global.fetch;
  const body = {
    messaging_product: 'whatsapp',
    to: normalizePhone(phone),
    type: 'interactive',
    interactive: {
      type: 'flow',
      header: { type: 'text', text: 'Alumni Directory Update' },
      body: { text: 'Dear Alumni, Amrita University is updating its official alumni directory. Please take a moment to verify and update your professional details. It only takes 2 minutes!' },
      footer: { text: 'Amrita Alumni Association' },
      action: {
        name: 'flow',
        parameters: {
          flow_message_version: '3',
          ...(FLOW_MODE === 'draft' ? { mode: 'draft' } : {}),
          flow_token: `alumni_${Date.now()}`,
          flow_id: FLOW_ID,
          flow_cta: 'Update My Profile',
          flow_action: 'navigate',
          flow_action_payload: { screen: 'LOOKUP' }
        }
      }
    }
  };
  const res = await fetchFn(`https://graph.facebook.com/v20.0/${PHONE_NUMBER_ID}/messages`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${WA_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
}

// ── WhatsApp Flow Webhook ──────────────────────────────────────────────────
app.post('/webhook', (req, res) => {
  try {
    const { body: payload, aesKey, iv, algo } = decryptRequest(req.body);
    const { action, screen, data, flow_token } = payload;
    console.log('Flow action:', action, '| Screen:', screen);
    let response;

    if (action === 'ping') {
      response = { data: { status: 'active' } };
    } else if (action === 'INIT') {
      const userPhone = data?.metadata?.wa_user_phone_number || '';
      response = {
        screen: 'LOOKUP',
        data: { phone_prefill: userPhone }
      };
    } else if (action === 'data_exchange') {
      if (screen === 'LOOKUP') {
        const phone = data?.phone || '';
        const alumni = findAlumni(phone);
        response = {
          screen: 'UPDATE',
          data: {
            full_name: alumni?.name || '', grad_year: alumni?.year || '',
            employer: alumni?.employer || '', designation: alumni?.designation || '',
            location: alumni?.location || '', email: alumni?.email || '',
            linkedin: alumni?.linkedin || '', lookup_phone: phone
          }
        };
      } else if (screen === 'UPDATE') {
        const phone = data?.lookup_phone || flow_token || '';
        upsertAlumni(phone, {
          name: data.full_name, year: data.grad_year,
          employer: data.employer, designation: data.designation,
          location: data.location, email: data.email, linkedin: data.linkedin
        });
        response = { screen: 'SUCCESS', data: {} };
      }
    }

    if (!response) response = { data: { error: 'Unknown action' } };
    res.setHeader('Content-Type', 'text/plain');
    res.send(encryptResponse(response, aesKey, iv, algo));
  } catch (err) {
    console.error('Webhook error:', err.message);
    res.status(500).send('Error');
  }
});

// ── Privacy Policy ────────────────────────────────────────────────────────
app.get('/privacy', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Privacy Policy - Amrita Alumni</title>
  <style>body{font-family:sans-serif;max-width:700px;margin:60px auto;padding:0 20px;color:#333;line-height:1.7}</style></head>
  <body><h1>Privacy Policy</h1><p><strong>Amrita Alumni Association</strong></p>
  <p>This WhatsApp-based alumni directory service collects alumni professional information (name, employer, designation, location, email, LinkedIn) solely for the purpose of maintaining the official Amrita University Alumni Directory.</p>
  <h2>Data Use</h2><ul>
  <li>Data is used exclusively for the alumni directory managed by Amrita Alumni Association.</li>
  <li>Data is not sold or shared with third parties.</li>
  <li>Alumni may request deletion of their data at any time.</li></ul>
  <h2>Contact</h2><p>For data requests contact: alumni@amrita.edu</p>
  <p style="color:#999;font-size:13px">Last updated: July 2026</p></body></html>`);
});

// ── Dashboard API ──────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', service: 'Amrita Alumni Flow Server' }));

app.get('/api/alumni', (req, res) => res.json(loadDb()));

app.post('/api/alumni', (req, res) => {
  const { name, phone, year, dept, employer, designation, location, email, linkedin } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone required' });
  upsertAlumni(phone, { name, year, dept, employer, designation, location, email, linkedin });
  res.json({ success: true });
});

app.delete('/api/alumni/:phone', (req, res) => {
  const db = loadDb();
  const p = normalizePhone(req.params.phone);
  const filtered = db.filter(a => normalizePhone(a.phone) !== p);
  saveDb(filtered);
  res.json({ success: true });
});

app.post('/api/alumni/import-csv', (req, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows)) return res.status(400).json({ error: 'rows array required' });
  const db = loadDb();
  let added = 0, updated = 0;
  for (const row of rows) {
    if (!row.phone) continue;
    const p = normalizePhone(row.phone);
    const idx = db.findIndex(a => normalizePhone(a.phone) === p);
    if (idx !== -1) {
      db[idx] = { ...db[idx], ...row, phone: p };
      updated++;
    } else {
      db.push({ ...row, phone: p, status: 'Pending', lastUpdated: '' });
      added++;
    }
  }
  saveDb(db);
  res.json({ success: true, added, updated });
});

app.get('/api/alumni/export-csv', (req, res) => {
  const db = loadDb();
  const headers = ['name', 'phone', 'year', 'dept', 'employer', 'designation', 'location', 'email', 'linkedin', 'status', 'lastUpdated'];
  const lines = [headers.join(',')];
  for (const a of db) {
    lines.push(headers.map(h => `"${(a[h] || '').replace(/"/g, '""')}"`).join(','));
  }
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="alumni_responses.csv"');
  res.send(lines.join('\n'));
});

app.post('/api/send-flow', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone required' });
  try {
    const result = await sendFlowToPhone(phone);
    if (result.messages) {
      const db = loadDb();
      const p = normalizePhone(phone);
      const idx = db.findIndex(a => normalizePhone(a.phone) === p);
      if (idx !== -1) { db[idx].flowSent = new Date().toISOString(); saveDb(db); }
    }
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/send-flow-all', async (req, res) => {
  const db = loadDb();
  const pending = db.filter(a => !a.flowSent && a.status !== 'Updated');
  const results = [];
  for (const a of pending) {
    try {
      const r = await sendFlowToPhone(a.phone);
      results.push({ phone: a.phone, success: !!r.messages, result: r });
      await new Promise(resolve => setTimeout(resolve, 1000));
    } catch (e) {
      results.push({ phone: a.phone, success: false, error: e.message });
    }
  }
  res.json({ sent: results.length, results });
});

// ── WhatsApp Incoming Message Webhook ─────────────────────────────────────
// Verification handshake
app.get('/wa-webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('Webhook verified');
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

// Receive incoming messages
app.post('/wa-webhook', (req, res) => {
  res.sendStatus(200); // always ack immediately
  try {
    const entry = req.body?.entry?.[0];
    const changes = entry?.changes?.[0];
    const value = changes?.value;
    if (!value) return;

    // Incoming messages from users
    const messages = value.messages || [];
    const contacts = value.contacts || [];
    for (const msg of messages) {
      const phone = msg.from;
      const name = contacts.find(c => c.wa_id === phone)?.profile?.name || phone;
      const text = msg.text?.body || msg.type || '[media]';
      // Update name in convs if we have it
      const convs = loadConvs();
      if (convs[phone]) convs[phone].name = name;
      saveConvs(convs);
      addMessage(phone, 'user', text, msg.type);
      console.log(`Incoming from ${phone} (${name}): ${text}`);
    }

    // Status updates (delivered, read, etc.)
    const statuses = value.statuses || [];
    for (const s of statuses) {
      console.log(`Status for ${s.recipient_id}: ${s.status}`);
    }
  } catch (e) {
    console.error('wa-webhook error:', e.message);
  }
});

// ── Conversations API ──────────────────────────────────────────────────────
app.get('/api/conversations', (req, res) => {
  const convs = loadConvs();
  const list = Object.values(convs).sort((a, b) =>
    (b.lastTs || '').localeCompare(a.lastTs || '')
  );
  res.json(list);
});

app.get('/api/conversations/:phone', (req, res) => {
  const convs = loadConvs();
  const conv = convs[req.params.phone];
  if (!conv) return res.status(404).json({ error: 'Not found' });
  res.json(conv);
});

app.post('/api/conversations/:phone/reply', async (req, res) => {
  const { text } = req.body;
  const phone = req.params.phone;
  if (!text) return res.status(400).json({ error: 'text required' });

  try {
    const { default: fetch } = await import('node-fetch');
    const r = await fetch(`https://graph.facebook.com/v20.0/${PHONE_NUMBER_ID}/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${WA_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messaging_product: 'whatsapp', to: phone,
        type: 'text', text: { body: text }
      })
    });
    const data = await r.json();
    if (data.messages) {
      addMessage(phone, 'admin', text);
      res.json({ success: true });
    } else {
      res.status(500).json({ error: data.error?.message || 'Send failed' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/conversations/:phone/handoff', (req, res) => {
  const convs = loadConvs();
  const phone = req.params.phone;
  if (!convs[phone]) convs[phone] = { phone, name: phone, messages: [], handoff: false };
  convs[phone].handoff = req.body.handoff;
  saveConvs(convs);
  res.json({ success: true, handoff: convs[phone].handoff });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Amrita Alumni server running on port ${PORT}`));
