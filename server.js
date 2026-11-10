const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Pega a URL do MongoDB configurada no Render (MONGO_URI)
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = "keyaccess_db";

// DEFINE A TUA PALAVRA-PASSE DE ADMIN AQUI (ou usa variável de ambiente)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "123456"; 

let db, keysCollection;

// Conectar à base de dados na nuvem
if (MONGO_URI) {
    MongoClient.connect(MONGO_URI)
        .then(client => {
            db = client.db(DB_NAME);
            keysCollection = db.collection('keys');
            console.log("Conectado ao MongoDB Atlas com sucesso!");
        })
        .catch(err => console.error("Erro ao conectar ao MongoDB:", err));
} else {
    console.warn("AVISO: MONGO_URI não definida nas variáveis de ambiente!");
}

// Middleware para verificar se a requisição de Admin é autorizada
function checkAdminAuth(req, res, next) {
    const authHeader = req.headers['x-admin-auth'];
    if (authHeader === ADMIN_PASSWORD) {
        return next();
    }
    return res.status(401).json({ error: "Acesso negado. Palavra-passe incorreta." });
}

// ================= API ENDPOINTS =================

// 1. Validar palavra-passe do Admin no Frontend
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        return res.json({ success: true, message: "Login efetuado com sucesso!" });
    }
    return res.status(401).json({ success: false, message: "Palavra-passe incorreta!" });
});

// 2. Listar todas as chaves (Protegido por Senha)
app.get('/api/admin/keys', checkAdminAuth, async (req, res) => {
    try {
        if (!keysCollection) return res.status(500).json({ error: "Base de dados não conectada" });
        const keys = await keysCollection.find({}).toArray();
        res.json(keys);
    } catch (err) {
        res.status(500).json({ error: "Erro ao buscar chaves" });
    }
});

// 3. Criar nova chave (Protegido por Senha)
app.post('/api/admin/keys', checkAdminAuth, async (req, res) => {
    try {
        if (!keysCollection) return res.status(500).json({ error: "Base de dados não conectada" });
        const { key, maxDevices, expiresAt } = req.body;
        
        const newKey = {
            key: key ? key.toUpperCase() : ('KEY-' + Math.random().toString(36).substring(2, 8).toUpperCase()),
            maxDevices: maxDevices || 3,
            devices: [],
            createdAt: new Date()
        };

        await keysCollection.insertOne(newKey);
        res.json({ success: true, message: "Chave criada com sucesso!", key: newKey });
    } catch (err) {
        res.status(500).json({ error: "Erro ao criar chave" });
    }
});

// 4. Apagar chave (Protegido por Senha)
app.delete('/api/admin/keys/:id', checkAdminAuth, async (req, res) => {
    try {
        if (!keysCollection) return res.status(500).json({ error: "Base de dados não conectada" });
        const id = req.params.id;
        await keysCollection.deleteOne({ _id: new ObjectId(id) });
        res.json({ success: true, message: "Chave removida!" });
    } catch (err) {
        res.status(500).json({ error: "Erro ao apagar chave" });
    }
});

// 5. Validar chave no Aplicativo Android (Público para os Apps)
app.post('/api/user/validate', async (req, res) => {
    try {
        if (!keysCollection) return res.status(500).json({ success: false, message: "Servidor indisponível" });
        
        const { key, hwid } = req.body;
        if (!key || !hwid) {
            return res.status(400).json({ success: false, message: "Chave ou HWID em falta." });
        }

        const keyData = await keysCollection.findOne({ key: key.toUpperCase() });
        if (!keyData) {
            return res.json({ success: false, message: "Chave inválida ou não encontrada." });
        }

        let devices = keyData.devices || [];

        if (devices.includes(hwid)) {
            return res.json({ success: true, message: "Acesso autorizado!" });
        }

        if (devices.length < (keyData.maxDevices || 3)) {
            devices.push(hwid);
            await keysCollection.updateOne(
                { _id: keyData._id },
                { $set: { devices: devices } }
            );
            return res.json({ success: true, message: "Dispositivo registado e autorizado!" });
        }

        return res.json({ success: false, message: "Limite máximo de aparelhos atingido." });

    } catch (err) {
        res.status(500).json({ success: false, message: "Erro interno no servidor." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor a correr na porta ${PORT}`);
});
