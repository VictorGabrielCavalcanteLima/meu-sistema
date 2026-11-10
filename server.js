const express = require('express');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Diz ao Express para servir os arquivos visuais da pasta 'public'
app.use(express.static('public'));

const SECRET_KEY = "sua_chave_secreta_super_segura_aqui";
const MAX_DEVICES = 3;
const DB_FILE = './database.json';

function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initialData = {
      keys: [],
      devices: [],
      admin: { password_hash: "" }
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

async function initAdmin() {
  let db = readDB();
  if (!db.admin.password_hash) {
    db.admin.password_hash = await bcrypt.hash("@Vitor259.0", 10);
    writeDB(db);
  }
}
initAdmin();

app.post('/api/user/validate', (req, res) => {
  const { key, hwid } = req.body;
  const now = Date.now();
  let db = readDB();

  let keyObj = db.keys.find(k => k.key_code === key);
  if (!keyObj) {
    return res.status(404).json({ success: false, message: "Chave inválida ou não encontrada." });
  }

  if (keyObj.activated_at && keyObj.expires_at && now > keyObj.expires_at) {
    keyObj.status = 'expired';
    writeDB(db);
    return res.status(403).json({ success: false, message: "Esta chave expirou." });
  }

  if (!keyObj.activated_at) {
    keyObj.activated_at = now;
    keyObj.expires_at = keyObj.duration_days > 0 ? now + (keyObj.duration_days * 86400000) : null;
  }

  let deviceList = db.devices.filter(d => d.key_id === keyObj.id);
  let hwids = deviceList.map(d => d.hwid);

  if (!hwids.includes(hwid)) {
    if (hwids.length >= MAX_DEVICES) {
      return res.status(403).json({ success: false, message: `Limite de ${MAX_DEVICES} dispositivos atingido.` });
    }
    db.devices.push({ key_id: keyObj.id, hwid });
  }

  writeDB(db);

  const token = jwt.sign({ keyId: keyObj.id, key: keyObj.key_code }, SECRET_KEY, { expiresIn: '12h' });
  return res.json({ success: true, message: "Acesso autorizado!", token, expires: keyObj.expires_at });
});

app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  let db = readDB();

  const isValid = await bcrypt.compare(password, db.admin.password_hash);
  if (!isValid) {
    return res.status(401).json({ success: false, message: "Senha incorreta." });
  }

  const token = jwt.sign({ role: 'admin' }, SECRET_KEY, { expiresIn: '2h' });
  res.json({ success: true, token });
});

function authenticateAdmin(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: "Acesso não autorizado." });

  jwt.verify(token.replace('Bearer ', ''), SECRET_KEY, (err, decoded) => {
    if (err || decoded.role !== 'admin') return res.status(403).json({ message: "Token inválido ou expirado." });
    next();
  });
}

app.post('/api/admin/create-key', authenticateAdmin, (req, res) => {
  const { customKey, durationDays } = req.body;
  let db = readDB();

  const keyCode = customKey || 'KEY-' + Math.random().toString(36).substring(2, 8).toUpperCase();
  
  if (db.keys.some(k => k.key_code === keyCode)) {
    return res.status(400).json({ success: false, message: "Chave já existe." });
  }

  const newKey = {
    id: db.keys.length > 0 ? db.keys[db.keys.length - 1].id + 1 : 1,
    key_code: keyCode,
    duration_days: durationDays || 0,
    activated_at: null,
    expires_at: null,
    status: 'active'
  };

  db.keys.push(newKey);
  writeDB(db);

  res.json({ success: true, message: "Chave criada com sucesso!", key: keyCode });
});

app.get('/api/admin/keys', authenticateAdmin, (req, res) => {
  let db = readDB();
  
  const keysWithCount = db.keys.map(k => {
    const device_count = db.devices.filter(d => d.key_id === k.id).length;
    return { ...k, device_count };
  });

  res.json({ success: true, keys: keysWithCount });
});

app.post('/api/admin/reset-hwid', authenticateAdmin, (req, res) => {
  const { keyId } = req.body;
  let db = readDB();

  db.devices = db.devices.filter(d => d.key_id !== keyId);
  writeDB(db);

  res.json({ success: true, message: "Dispositivos resetados!" });
});

app.delete('/api/admin/delete-key/:id', authenticateAdmin, (req, res) => {
  const keyId = parseInt(req.params.id);
  let db = readDB();

  db.keys = db.keys.filter(k => k.id !== keyId);
  db.devices = db.devices.filter(d => d.key_id !== keyId);
  writeDB(db);

  res.json({ success: true, message: "Chave excluída!" });
});

app.listen(3000, () => {
  console.log("Servidor rodando com JSON na porta 3000!");
});
