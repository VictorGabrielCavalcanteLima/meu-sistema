const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = "keyaccess_db";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "123456";

let db, keysCollection, resellersCollection, logsCollection;

if (MONGO_URI) {
    MongoClient.connect(MONGO_URI)
        .then(client => {
            db = client.db(DB_NAME);
            keysCollection = db.collection('keys');
            resellersCollection = db.collection('resellers');
            logsCollection = db.collection('logs');
            console.log("Conectado ao MongoDB Atlas com sucesso!");
        })
        .catch(err => console.error("Erro ao conectar ao MongoDB:", err));
}

// Helper para guardar logs de atividade
async function addLog(action, details) {
    if (logsCollection) {
        await logsCollection.insertOne({ action, details, timestamp: new Date() });
    }
}

// ================= API ENDPOINTS =================

// 1. Login Admin ou Revendedor
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        return res.json({ success: true, role: 'admin', token: ADMIN_PASSWORD });
    }
    
    if (resellersCollection) {
        const reseller = await resellersCollection.findOne({ username, password });
        if (reseller) {
            return res.json({ success: true, role: 'reseller', username: reseller.username, credits: reseller.credits });
        }
    }
    return res.status(401).json({ success: false, message: "Credenciais inválidas!" });
});

// 2. Dashboard Stats & Keys (Admin)
app.get('/api/admin/dashboard', async (req, res) => {
    try {
        const totalKeys = await keysCollection.countDocuments({});
        const activeKeys = await keysCollection.countDocuments({ bof: { $ne: true } });
        const bannedKeys = await keysCollection.countDocuments({ banned: true });
        const keys = await keysCollection.find({}).toArray();
        const resellers = resellersCollection ? await resellersCollection.find({}).toArray() : [];
        const logs = logsCollection ? await logsCollection.find({}).sort({ timestamp: -1 }).limit(10).toArray() : [];

        res.json({ stats: { totalKeys, activeKeys, bannedKeys }, keys, resellers, logs });
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar dados do dashboard" });
    }
});

// 3. Criar Chave (Admin ou Revendedor)
app.post('/api/keys/create', async (req, res) => {
    try {
        const { durationDays, maxDevices, resellerUser } = req.body;
        
        // Se for revendedor, desconta créditos
        if (resellerUser) {
            const reseller = await resellersCollection.findOne({ username: resellerUser });
            if (!reseller || reseller.credits <= 0) {
                return res.status(400).json({ success: false, message: "Créditos insuficientes!" });
            }
            await resellersCollection.updateOne({ username: resellerUser }, { $inc: { credits: -1 } });
        }

        const keyString = 'KEY-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
        
        let expiresAt = null;
        if (durationDays && durationDays > 0) {
            expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + parseInt(durationDays));
        }

        const newKey = {
            key: keyString,
            durationDays: durationDays || 0,
            expiresAt: expiresAt,
            maxDevices: maxDevices || 3,
            devices: [],
            banned: false,
            createdAt: new Date(),
            createdBy: resellerUser || 'admin'
        };

        await keysCollection.insertOne(newKey);
        await addLog("Criação de Chave", `Chave ${keyString} criada por ${resellerUser || 'Admin'}`);
        res.json({ success: true, key: newKey });
    } catch (err) {
        res.status(500).json({ success: false, error: "Erro ao criar chave" });
    }
});

// 4. Ações na Chave (Banir, Reset HWID, Apagar)
app.post('/api/keys/action', async (req, res) => {
    const { keyId, action } = req.body;
    try {
        if (action === 'delete') {
            await keysCollection.deleteOne({ _id: new ObjectId(keyId) });
            await addLog("Remoção", `Chave ID ${keyId} apagada.`);
        } else if (action === 'ban') {
            const keyData = await keysCollection.findOne({ _id: new ObjectId(keyId) });
            const newStatus = !keyData.banned;
            await keysCollection.updateOne({ _id: new ObjectId(keyId) }, { $set: { banned: newStatus } });
            await addLog("Banimento", `Chave ${keyData.key} status banido: ${newStatus}`);
        } else if (action === 'reset_hwid') {
            await keysCollection.updateOne({ _id: new ObjectId(keyId) }, { $set: { devices: [] } });
            await addLog("Reset HWID", `Dispositivos limpos para a chave ID ${keyId}`);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: "Erro na ação" });
    }
});

// 5. Criar Conta de Revendedor (Admin)
app.post('/api/admin/reseller/create', async (req, res) => {
    const { username, password, credits } = req.body;
    try {
        await resellersCollection.insertOne({ username, password, credits: parseInt(credits) || 10, createdAt: new Date() });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: "Erro ao criar revendedor" });
    }
});

// 6. Validação de Chave no App Android (Com verificação de expiração e ban)
app.post('/api/user/validate', async (req, res) => {
    try {
        const { key, hwid } = req.body;
        if (!key || !hwid) return res.status(400).json({ success: false, message: "Dados incompletos." });

        const keyData = await keysCollection.findOne({ key: key.toUpperCase() });
        if (!keyData) return res.json({ success: false, message: "Chave inválida." });

        if (keyData.banned) return res.json({ success: false, message: "Esta chave foi banida pelo administrador." });

        // Verificar Expiração por Data
        if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
            return res.json({ success: false, message: "A assinatura desta chave expirou." });
        }

        let devices = keyData.devices || [];
        if (devices.includes(hwid)) {
            return res.json({ success: true, message: "Acesso autorizado!" });
        }

        if (devices.length < (keyData.maxDevices || 3)) {
            devices.push(hwid);
            await keysCollection.updateOne({ _id: keyData._id }, { $set: { devices: devices } });
            return res.json({ success: true, message: "Dispositivo registado com sucesso!" });
        }

        return res.json({ success: false, message: "Limite máximo de aparelhos atingido." });
    } catch (err) {
        res.status(500).json({ success: false, message: "Erro interno no servidor." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor profissional a correr na porta ${PORT}`));
