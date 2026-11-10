const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const DB_NAME = "keyaccess_db";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "123456";

let db, keysCollection, resellersCollection, logsCollection;

// Sanitiza e trata a string do MongoDB antes da conexão
function cleanMongoUri(rawUri) {
    if (!rawUri) return "";
    let uri = rawUri.trim();

    // Se for mongodb+srv, remove portas indevidas (ex: :27017)
    if (uri.startsWith("mongodb+srv://")) {
        uri = uri.replace(/:[0-9]+(\/|\?|$)/, "$1");
    }

    // Corrige o @ no e-mail de utilizador se não estiver codificado como %40
    if (uri.includes("gmail.com") && !uri.includes("gmail.com%40") && uri.includes("@gmail.com:")) {
        uri = uri.replace("@gmail.com:", "%40gmail.com:");
    }

    return uri;
}

// Inicia o servidor Express primeiro para garantir estabilidade no Render
app.listen(PORT, () => {
    console.log(`Servidor Web ativo na porta ${PORT}`);
    connectDatabase();
});

async function connectDatabase() {
    const rawUri = process.env.MONGO_URI;
    const uri = cleanMongoUri(rawUri);

    if (!uri) {
        console.error("AVISO: MONGO_URI não definida nas variáveis de ambiente!");
        return;
    }

    try {
        const client = new MongoClient(uri);
        await client.connect();
        db = client.db(DB_NAME);
        keysCollection = db.collection('keys');
        resellersCollection = db.collection('resellers');
        logsCollection = db.collection('logs');
        console.log("Conectado ao MongoDB Atlas com sucesso!");
    } catch (err) {
        console.error("Erro ao conectar ao MongoDB:", err.message);
    }
}

async function addLog(action, details) {
    try {
        if (logsCollection) {
            await logsCollection.insertOne({ action, details, timestamp: new Date() });
        }
    } catch (e) {}
}

// ================= API ENDPOINTS =================

// LOGIN ADMIN / REVENDEDOR
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
        res.status(500).json({ error: "Erro ao carregar dashboard" });
    }
});

// CRIAR CHAVE
app.post('/api/keys/create', async (req, res) => {
    try {
        if (!keysCollection) return res.status(500).json({ success: false, message: "Aguardando conexão com o banco..." });

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

// AÇÕES DA CHAVE (BANIR, HWID RESET, DELETE)
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
        if (!resellersCollection) return res.status(500).json({ success: false, message: "Aguardando conexão com o banco..." });

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

// VALIDAÇÃO DE LICENÇA (APP)
app.post('/api/user/validate', async (req, res) => {
    try {
        if (!keysCollection) return res.status(500).json({ success: false, message: "Aguardando conexão com o banco..." });

        const { key, hwid } = req.body;
        if (!key || !hwid) return res.status(400).json({ success: false, message: "Dados incompletos." });

        const keyData = await keysCollection.findOne({ key: key.toUpperCase() });
        if (!keyData) return res.json({ success: false, message: "Chave inválida." });

        if (keyData.banned) return res.json({ success: false, message: "Chave banida pelo administrador." });
        if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
            return res.json({ success: false, message: "Licença expirada." });
        }

        let devices = keyData.devices || [];
        if (devices.includes(hwid)) return res.json({ success: true, message: "Acesso autorizado!" });

        if (devices.length < (keyData.maxDevices || 3)) {
            devices.push(hwid);
            await keysCollection.updateOne({ _id: keyData._id }, { $set: { devices: devices } });
            return res.json({ success: true, message: "Dispositivo registrado!" });
        }

        return res.json({ success: false, message: "Limite de dispositivos atingido." });
    } catch (err) {
        res.status(500).json({ success: false, message: "Erro interno no servidor." });
    }
});
