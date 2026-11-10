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

async function startServer() {
    if (!MONGO_URI) {
        console.error("ERRO CRÍTICO: MONGO_URI não está definida nas variáveis do Render!");
    }
    try {
        const client = new MongoClient(MONGO_URI);
        await client.connect();
        db = client.db(DB_NAME);
        keysCollection = db.collection('keys');
        resellersCollection = db.collection('resellers');
        logsCollection = db.collection('logs');
        console.log("Conectado ao MongoDB Atlas com sucesso!");
    } catch (err) {
        console.error("Falha ao ligar ao MongoDB:", err);
    }

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Servidor a correr na porta ${PORT}`));
}
startServer();

async function addLog(action, details) {
    try {
        if (logsCollection) {
            await logsCollection.insertOne({ action, details, timestamp: new Date() });
        }
    } catch (e) {}
}

// LOGIN
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        return res.json({ success: true, role: 'admin', token: ADMIN_PASSWORD });
    }
    try {
        if (resellersCollection) {
            const reseller = await resellersCollection.findOne({ username, password });
            if (reseller) {
                return res.json({ success: true, role: 'reseller', username: reseller.username, credits: reseller.credits });
            }
        }
    } catch (e) {}
    return res.status(401).json({ success: false, message: "Credenciais inválidas!" });
});

// DASHBOARD DATA
app.get('/api/admin/dashboard', async (req, res) => {
    try {
        if (!keysCollection) {
            return res.json({ stats: { totalKeys: 0, activeKeys: 0, bannedKeys: 0 }, keys: [], resellers: [], logs: [] });
        }
        const totalKeys = await keysCollection.countDocuments({});
        const activeKeys = await keysCollection.countDocuments({ banned: { $ne: true } });
        const bannedKeys = await keysCollection.countDocuments({ banned: true });
        const keys = await keysCollection.find({}).toArray();
        const resellers = resellersCollection ? await resellersCollection.find({}).toArray() : [];
        const logs = logsCollection ? await logsCollection.find({}).sort({ timestamp: -1 }).limit(10).toArray() : [];

        res.json({ stats: { totalKeys, activeKeys, bannedKeys }, keys, resellers, logs });
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar dados" });
    }
});

// CRIAR CHAVE
app.post('/api/keys/create', async (req, res) => {
    try {
        if (!keysCollection) return res.status(500).json({ success: false, message: "Base de dados indisponível." });
        
        const { durationDays, maxDevices, resellerUser } = req.body;
        
        if (resellerUser && resellersCollection) {
            const reseller = await resellersCollection.findOne({ username: resellerUser });
            if (!reseller || reseller.credits <= 0) {
                return res.status(400).json({ success: false, message: "Créditos insuficientes!" });
            }
            await resellersCollection.updateOne({ username: resellerUser }, { $inc: { credits: -1 } });
        }

        const keyString = 'KEY-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
        
        let expiresAt = null;
        if (durationDays && parseInt(durationDays) > 0) {
            expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + parseInt(durationDays));
        }

        const newKey = {
            key: keyString,
            durationDays: parseInt(durationDays) || 0,
            expiresAt: expiresAt,
            maxDevices: parseInt(maxDevices) || 3,
            devices: [],
            banned: false,
            createdAt: new Date(),
            createdBy: resellerUser || 'admin'
        };

        await keysCollection.insertOne(newKey);
        await addLog("Criação", `Chave ${keyString} criada por ${resellerUser || 'Admin'}`);
        res.json({ success: true, key: newKey });
    } catch (err) {
        res.status(500).json({ success: false, error: "Erro ao criar chave" });
    }
});

// AÇÕES DA CHAVE
app.post('/api/keys/action', async (req, res) => {
    const { keyId, action } = req.body;
    try {
        if (!keysCollection) return res.status(500).json({ success: false });

        if (action === 'delete') {
            await keysCollection.deleteOne({ _id: new ObjectId(keyId) });
        } else if (action === 'ban') {
            const keyData = await keysCollection.findOne({ _id: new ObjectId(keyId) });
            if (keyData) {
                await keysCollection.updateOne({ _id: new ObjectId(keyId) }, { $set: { banned: !keyData.banned } });
            }
        } else if (action === 'reset_hwid') {
            await keysCollection.updateOne({ _id: new ObjectId(keyId) }, { $set: { devices: [] } });
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// CRIAR REVENDEDOR
app.post('/api/admin/reseller/create', async (req, res) => {
    const { username, password, credits } = req.body;
    try {
        if (!resellersCollection) return res.status(500).json({ success: false, message: "Base de dados indisponível." });
        
        await resellersCollection.insertOne({ 
            username, 
            password, 
            credits: parseInt(credits) || 10, 
            createdAt: new Date() 
        });
        await addLog("Revendedor", `Criado: ${username}`);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: "Erro ao criar revendedor" });
    }
});

// VALIDAR CHAVE APP
app.post('/api/user/validate', async (req, res) => {
    try {
        if (!keysCollection) return res.status(500).json({ success: false, message: "Servidor a iniciar..." });

        const { key, hwid } = req.body;
        const keyData = await keysCollection.findOne({ key: key.toUpperCase() });
        if (!keyData) return res.json({ success: false, message: "Chave inválida." });

        if (keyData.banned) return res.json({ success: false, message: "Chave banida." });
        if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
            return res.json({ success: false, message: "Chave expirada." });
        }

        let devices = keyData.devices || [];
        if (devices.includes(hwid)) return res.json({ success: true, message: "Acesso autorizado!" });

        if (devices.length < (keyData.maxDevices || 3)) {
            devices.push(hwid);
            await keysCollection.updateOne({ _id: keyData._id }, { $set: { devices: devices } });
            return res.json({ success: true, message: "Dispositivo registado!" });
        }

        return res.json({ success: false, message: "Limite de aparelhos atingido." });
    } catch (err) {
        res.status(500).json({ success: false, message: "Erro interno." });
    }
});
