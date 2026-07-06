const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { MongoClient } = require('mongodb');

const BANNER_B64 = (() => {
  try {
    const img = fs.readFileSync(path.join(__dirname, 'public', 'amrita_banner_small.jpg'));
    return 'data:image/jpeg;base64,' + img.toString('base64');
  } catch { return ''; }
})();

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Private key: base64 env var (Railway) → escaped-newline env var → local file
const PRIVATE_KEY = process.env.PRIVATE_KEY_B64
  ? Buffer.from(process.env.PRIVATE_KEY_B64, 'base64').toString('utf8')
  : process.env.PRIVATE_KEY
    ? process.env.PRIVATE_KEY.replace(/\\n/g, '\n')
    : fs.readFileSync(path.join(__dirname, 'private.pem'), 'utf8');

const VERIFY_TOKEN    = process.env.VERIFY_TOKEN    || 'amrita_verify_2024';
const WA_TOKEN        = process.env.WA_TOKEN        || '';
const PHONE_NUMBER_ID = process.env.PHONE_NUMBER_ID || '1181292345065359';
const FLOW_ID         = process.env.FLOW_ID         || '1571206234422583';
const FLOW_MODE       = process.env.FLOW_MODE       || 'published';
const MONGODB_URI     = process.env.MONGODB_URI     || process.env.MONGO_URI || '';

// ── MongoDB ───────────────────────────────────────────────────────────────
let mongoDb;
async function getDb() {
  if (!mongoDb) {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    mongoDb = client.db('amrita_alumni');
    await mongoDb.collection('alumni').createIndex({ phone: 1 }, { unique: true });
    console.log('MongoDB connected');
  }
  return mongoDb;
}

function normalizePhone(phone) {
  return String(phone).replace(/[\s+\-()]/g, '');
}

function phoneFilter(p) {
  return { $or: [{ phone: p }, { phone: '91' + p }, { phone: p.replace(/^91/, '') }] };
}

async function findAlumni(phone) {
  const db = await getDb();
  const p = normalizePhone(phone);
  return db.collection('alumni').findOne(phoneFilter(p));
}

async function upsertAlumni(phone, fields) {
  const db = await getDb();
  const p = normalizePhone(phone);
  const existing = await db.collection('alumni').findOne(phoneFilter(p));
  const timestamp = new Date().toISOString();
  if (existing) {
    await db.collection('alumni').updateOne(
      { _id: existing._id },
      { $set: { ...fields, status: 'Updated', lastUpdated: timestamp } }
    );
  } else {
    await db.collection('alumni').insertOne({ phone: p, ...fields, status: 'New', lastUpdated: timestamp });
  }
}

async function loadAllAlumni() {
  const db = await getDb();
  return db.collection('alumni').find({}).toArray();
}

async function deleteAlumni(phone) {
  const db = await getDb();
  const p = normalizePhone(phone);
  await db.collection('alumni').deleteOne(phoneFilter(p));
}

async function importAlumniRows(rows) {
  const db = await getDb();
  let added = 0, updated = 0;
  for (const row of rows) {
    if (!row.phone) continue;
    const p = normalizePhone(row.phone);
    const existing = await db.collection('alumni').findOne({ phone: p });
    if (existing) {
      await db.collection('alumni').updateOne({ phone: p }, { $set: { ...row, phone: p } });
      updated++;
    } else {
      await db.collection('alumni').insertOne({ ...row, phone: p, status: 'Pending', lastUpdated: '' });
      added++;
    }
  }
  return { added, updated };
}

async function getConv(phone) {
  const db = await getDb();
  return db.collection('conversations').findOne({ phone });
}

async function saveConvField(phone, fields) {
  const db = await getDb();
  await db.collection('conversations').updateOne(
    { phone },
    { $set: fields },
    { upsert: true }
  );
}

async function addMessage(phone, from, text, type = 'text') {
  const db = await getDb();
  const alumni = await findAlumni(phone);
  const msg = { from, text, type, ts: new Date().toISOString() };
  await db.collection('conversations').updateOne(
    { phone },
    {
      $push: { messages: msg },
      $set: { lastMessage: text, lastTs: msg.ts },
      $setOnInsert: { name: alumni?.name || phone, handoff: false }
    },
    { upsert: true }
  );
}

// ── Encryption ────────────────────────────────────────────────────────────
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

// ── WhatsApp API helpers ──────────────────────────────────────────────────
async function sendTemplateToPhone(phone) {
  const { default: fetch } = await import('node-fetch').catch(() => ({ default: null }));
  const fetchFn = fetch || global.fetch;
  const alumni = await findAlumni(phone);
  const name = alumni?.name || 'Alumni';
  const body = {
    messaging_product: 'whatsapp',
    to: normalizePhone(phone),
    type: 'template',
    template: {
      name: 'alumni_directory_update',
      language: { code: 'en' },
      components: [
        {
          type: 'header',
          parameters: [{ type: 'image', image: { link: 'https://amritaalumnichatbot-production.up.railway.app/amrita_banner.jpg' } }]
        },
        {
          type: 'body',
          parameters: [
            { type: 'text', text: name },
            { type: 'text', text: 'Jay, Sreejith' }
          ]
        },
        { type: 'button', sub_type: 'flow', index: '0', parameters: [] }
      ]
    }
  };
  const res = await fetchFn(`https://graph.facebook.com/v20.0/${PHONE_NUMBER_ID}/messages`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${WA_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
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
      body: { text: 'Tap below to update your alumni profile.' },
      footer: { text: 'Amrita Alumni Association' },
      action: {
        name: 'flow',
        parameters: {
          flow_message_version: '3',
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

// ── WhatsApp Flow Webhook ─────────────────────────────────────────────────
app.post('/webhook', async (req, res) => {
  try {
    const { body: payload, aesKey, iv, algo } = decryptRequest(req.body);
    const { action, screen, data, flow_token } = payload;
    console.log('Flow action:', action, '| Screen:', screen);
    let response;

    if (action === 'ping') {
      response = { data: { status: 'active' } };
    } else if (action === 'INIT') {
      const userPhone = data?.metadata?.wa_user_phone_number || '';
      response = { screen: 'LOOKUP', data: { phone_prefill: userPhone } };
    } else if (action === 'data_exchange') {
      if (screen === 'LOOKUP') {
        const phone = data?.phone || '';
        const alumni = await findAlumni(phone);
        response = {
          screen: 'UPDATE',
          data: {
            full_name: alumni?.name || '', grad_year: alumni?.year || '',
            employer: alumni?.employer || '', designation: alumni?.designation || '',
            location: alumni?.location || '', email: alumni?.email || '',
            linkedin: alumni?.linkedin || '', lookup_phone: phone,
            image_src: BANNER_B64
          }
        };
      } else if (screen === 'UPDATE') {
        const phone = data?.lookup_phone || flow_token || '';
        await upsertAlumni(phone, {
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
  <p>This WhatsApp-based alumni directory service collects alumni professional information solely for maintaining the official Amrita University Alumni Directory.</p>
  <h2>Data Use</h2><ul>
  <li>Data is used exclusively for the alumni directory managed by Amrita Alumni Association.</li>
  <li>Data is not sold or shared with third parties.</li>
  <li>Alumni may request deletion of their data at any time.</li></ul>
  <h2>Contact</h2><p>For data requests contact: alumni@amrita.edu</p>
  <p style="color:#999;font-size:13px">Last updated: July 2026</p></body></html>`);
});

// ── Dashboard API ─────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', service: 'Amrita Alumni Flow Server' }));

app.get('/api/alumni', async (req, res) => {
  try { res.json(await loadAllAlumni()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/alumni', async (req, res) => {
  const { name, phone, year, dept, employer, designation, location, email, linkedin } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone required' });
  try {
    await upsertAlumni(phone, { name, year, dept, employer, designation, location, email, linkedin });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/alumni/:phone', async (req, res) => {
  try {
    await deleteAlumni(req.params.phone);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/alumni/import-csv', async (req, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows)) return res.status(400).json({ error: 'rows array required' });
  try {
    const result = await importAlumniRows(rows);
    res.json({ success: true, ...result });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/alumni/export-csv', async (req, res) => {
  try {
    const db = await loadAllAlumni();
    const headers = ['name', 'phone', 'year', 'dept', 'employer', 'designation', 'location', 'email', 'linkedin', 'status', 'lastUpdated'];
    const lines = [headers.join(',')];
    for (const a of db) {
      lines.push(headers.map(h => `"${(a[h] || '').replace(/"/g, '""')}"`).join(','));
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="alumni_responses.csv"');
    res.send(lines.join('\n'));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/send-flow', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone required' });
  try {
    const result = await sendTemplateToPhone(phone);
    if (result.messages) {
      await upsertAlumni(phone, { flowSent: new Date().toISOString() });
    }
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/send-flow-all', async (req, res) => {
  try {
    const all = await loadAllAlumni();
    const pending = all.filter(a => !a.flowSent && a.status !== 'Updated');
    const results = [];
    for (const a of pending) {
      try {
        const r = await sendTemplateToPhone(a.phone);
        results.push({ phone: a.phone, success: !!r.messages, result: r });
        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (e) {
        results.push({ phone: a.phone, success: false, error: e.message });
      }
    }
    res.json({ sent: results.length, results });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── WhatsApp Incoming Webhook ─────────────────────────────────────────────
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

app.post('/wa-webhook', (req, res) => {
  res.sendStatus(200);
  try {
    const entry = req.body?.entry?.[0];
    const value = entry?.changes?.[0]?.value;
    if (!value) return;

    const messages = value.messages || [];
    const contacts = value.contacts || [];
    for (const msg of messages) {
      const phone = msg.from;
      const name = contacts.find(c => c.wa_id === phone)?.profile?.name || phone;
      const text = msg.text?.body || msg.button?.text || msg.type || '[media]';
      addMessage(phone, 'user', text, msg.type).catch(e => console.error('addMessage error:', e.message));
      saveConvField(phone, { name }).catch(() => {});
      console.log(`Incoming from ${phone} (${name}): ${text}`);

      const isUpdateNow = msg.type === 'button' && msg.button?.text?.toLowerCase().includes('update');
      if (isUpdateNow) {
        sendFlowToPhone(phone).catch(e => console.error('Auto-flow error:', e.message));
      }
    }

    const statuses = value.statuses || [];
    for (const s of statuses) {
      console.log(`Status for ${s.recipient_id}: ${s.status}`);
    }
  } catch (e) {
    console.error('wa-webhook error:', e.message);
  }
});

// ── Conversations API ─────────────────────────────────────────────────────
app.get('/api/conversations', async (req, res) => {
  try {
    const db = await getDb();
    const list = await db.collection('conversations').find({}).sort({ lastTs: -1 }).toArray();
    res.json(list);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/conversations/:phone', async (req, res) => {
  try {
    const conv = await getConv(req.params.phone);
    if (!conv) return res.status(404).json({ error: 'Not found' });
    res.json(conv);
  } catch (e) { res.status(500).json({ error: e.message }); }
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
      body: JSON.stringify({ messaging_product: 'whatsapp', to: phone, type: 'text', text: { body: text } })
    });
    const data = await r.json();
    if (data.messages) {
      await addMessage(phone, 'admin', text);
      res.json({ success: true });
    } else {
      res.status(500).json({ error: data.error?.message || 'Send failed' });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/conversations/:phone/handoff', async (req, res) => {
  const phone = req.params.phone;
  try {
    await saveConvField(phone, { handoff: req.body.handoff });
    res.json({ success: true, handoff: req.body.handoff });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Amrita Alumni server running on port ${PORT}`));
