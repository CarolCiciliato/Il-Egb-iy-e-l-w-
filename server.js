require('dotenv').config();
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'ile_egbe_secret_key_2026',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Servir arquivos estáticos da raiz do projeto
app.use(express.static(__dirname));

// Configuração do Banco de Dados SQLite
const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) {
        console.error('Erro ao abrir o banco de dados:', err.message);
    } else {
        console.log('Conectado ao banco de dados SQLite.');
        inicializarBanco();
    }
});

function inicializarBanco() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS administradores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            reset_token TEXT,
            reset_token_expires DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );`);

        db.run(`CREATE TABLE IF NOT EXISTS giras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dia TEXT NOT NULL,
            mes TEXT NOT NULL,
            dia_semana TEXT NOT NULL,
            horario TEXT NOT NULL,
            nome TEXT NOT NULL,
            categoria TEXT NOT NULL
        );`);

        db.run(`CREATE TABLE IF NOT EXISTS horarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT NOT NULL,
            horario TEXT NOT NULL,
            servico TEXT NOT NULL,
            status TEXT DEFAULT 'Disponível'
        );`);

        db.run(`CREATE TABLE IF NOT EXISTS agendamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            telefone TEXT NOT NULL,
            servico TEXT NOT NULL,
            data TEXT NOT NULL,
            horario_id INTEGER,
            horario TEXT NOT NULL,
            mensagem TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );`);
    });
}

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT || '465'),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middleware de Setup Wizard: Se não houver administradores, redireciona para /setup.html
app.use((req, res, next) => {
    if (req.path.startsWith('/api/') || req.path === '/setup.html' || req.path.endsWith('.css') || req.path.endsWith('.js')) {
        return next();
    }

    db.get(`SELECT COUNT(*) as count FROM administradores`, (err, row) => {
        if (err) return next();
        if (row && row.count === 0 && req.path !== '/setup.html') {
            return res.redirect('/setup.html');
        }
        if (row && row.count > 0 && req.path === '/setup.html') {
            return res.redirect('/login.html');
        }
        next();
    });
});

// Middleware de Autenticação para Rotas Protegidas do Painel
function verificarAutenticacao(req, res, next) {
    if (req.session && req.session.adminId) {
        return next();
    }
    return res.status(401).json({ error: 'Acesso não autorizado. Faça login.' });
}

// ================= ROTAS DE SETUP E AUTH =================

app.get('/api/setup/status', (req, res) => {
    db.get(`SELECT COUNT(*) as count FROM administradores`, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ needsSetup: row.count === 0 });
    });
});

app.post('/api/setup', async (req, res) => {
    const { nome, email, senha } = req.body;
    if (!nome || !email || !senha) {
        return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
    }

    db.get(`SELECT COUNT(*) as count FROM administradores`, async (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row.count > 0) {
            return res.status(403).json({ error: 'Setup já realizado anteriormente.' });
        }

        try {
            const hashedPassword = await bcrypt.hash(senha, 10);
            db.run(`INSERT INTO administradores (nome, email, senha) VALUES (?, ?, ?)`, [nome, email, hashedPassword], function(err) {
                if (err) return res.status(400).json({ error: 'E-mail já cadastrado ou erro ao salvar.' });
                res.json({ message: 'Administrador Master cadastrado com sucesso!' });
            });
        } catch (e) {
            res.status(500).json({ error: 'Erro ao criptografar senha.' });
        }
    });
});

app.post('/api/auth/login', (req, res) => {
    const { email, senha } = req.body;
    db.get(`SELECT * FROM administradores WHERE email = ?`, [email], async (err, admin) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!admin) return res.status(401).json({ error: 'E-mail ou senha inválidos.' });

        const senhaValidada = await bcrypt.compare(senha, admin.senha);
        if (!senhaValidada) return res.status(401).json({ error: 'E-mail ou senha inválidos.' });

        req.session.adminId = admin.id;
        req.session.adminNome = admin.nome;
        req.session.adminEmail = admin.email;
        res.json({ message: 'Login realizado com sucesso!', nome: admin.nome });
    });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ message: 'Logout realizado com sucesso.' });
    });
});

app.get('/api/auth/me', verificarAutenticacao, (req, res) => {
    res.json({ id: req.session.adminId, nome: req.session.adminNome, email: req.session.adminEmail });
});

app.post('/api/auth/esqueci-senha', (req, res) => {
    const { email } = req.body;
    db.get(`SELECT * FROM administradores WHERE email = ?`, [email], (err, admin) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!admin) {
            return res.json({ message: 'Se o e-mail estiver cadastrado, você receberá as instruções de recuperação.' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 3600000).toISOString();

        db.run(`UPDATE administradores SET reset_token = ?, reset_token_expires = ? WHERE id = ?`, [token, expires, admin.id], async (err) => {
            if (err) return res.status(500).json({ error: 'Erro ao gerar token de recuperação.' });

            const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
            const resetLink = `${baseUrl}/redefinir-senha.html?token=${token}`;

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: admin.email,
                subject: 'Ilê Egbé - Recuperação de Senha',
                html: `
                    <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
                        <h2 style="color: #5c3a21;">Recuperação de Senha - Ilê Egbé</h2>
                        <p>Olá, <strong>${admin.nome}</strong>,</p>
                        <p>Você solicitou a recuperação de senha para acessar o painel administrativo.</p>
                        <p>Clique no botão abaixo para redefinir sua senha (o link expira em 1 hora):</p>
                        <a href="${resetLink}" style="background-color: #5c3a21; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 15px 0;">Redefinir Senha</a>
                        <p>Se você não solicitou isso, por favor ignore este e-mail.</p>
                    </div>
                `
            };

            try {
                await transporter.sendMail(mailOptions);
                res.json({ message: 'E-mail de recuperação enviado com sucesso!' });
            } catch (mailErr) {
                console.error('Erro ao enviar e-mail:', mailErr);
                res.status(500).json({ error: 'Erro ao enviar e-mail de recuperação. Verifique as credenciais no .env.' });
            }
        });
    });
});

app.post('/api/auth/redefinir-senha', async (req, res) => {
    const { token, novaSenha } = req.body;
    if (!token || !novaSenha) {
        return res.status(400).json({ error: 'Token e nova senha são obrigatórios.' });
    }

    const agora = new Date().toISOString();
    db.get(`SELECT * FROM administradores WHERE reset_token = ? AND reset_token_expires > ?`, [token, agora], async (err, admin) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!admin) return res.status(400).json({ error: 'Token inválido ou expirado.' });

        try {
            const hashedPassword = await bcrypt.hash(novaSenha, 10);
            db.run(`UPDATE administradores SET senha = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?`, [hashedPassword, admin.id], (err) => {
                if (err) return res.status(500).json({ error: 'Erro ao atualizar senha.' });
                res.json({ message: 'Senha redefinida com sucesso!' });
            });
        } catch (e) {
            res.status(500).json({ error: 'Erro ao processar nova senha.' });
        }
    });
});

app.post('/api/auth/alterar-senha', verificarAutenticacao, async (req, res) => {
    const { senhaAntiga, novaSenha } = req.body;
    db.get(`SELECT * FROM administradores WHERE id = ?`, [req.session.adminId], async (err, admin) => {
        if (err) return res.status(500).json({ error: err.message });

        const match = await bcrypt.compare(senhaAntiga, admin.senha);
        if (!match) return res.status(400).json({ error: 'Senha antiga incorreta.' });

        try {
            const hashed = await bcrypt.hash(novaSenha, 10);
            db.run(`UPDATE administradores SET senha = ? WHERE id = ?`, [hashed, admin.id], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: 'Senha alterada com sucesso!' });
            });
        } catch (e) {
            res.status(500).json({ error: 'Erro ao atualizar senha.' });
        }
    });
});

// ================= ROTAS DE GESTÃO DE ADMINISTRADORES =================

app.get('/api/administradores', verificarAutenticacao, (req, res) => {
    db.all(`SELECT id, nome, email, created_at FROM administradores`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/administradores', verificarAutenticacao, async (req, res) => {
    const { nome, email, senha } = req.body;
    if (!nome || !email || !senha) return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });

    try {
        const hashed = await bcrypt.hash(senha, 10);
        db.run(`INSERT INTO administradores (nome, email, senha) VALUES (?, ?, ?)`, [nome, email, hashed], function(err) {
            if (err) return res.status(400).json({ error: 'E-mail já cadastrado.' });
            res.json({ message: 'Administrador cadastrado com sucesso!' });
        });
    } catch (e) {
        res.status(500).json({ error: 'Erro ao cadastrar administrador.' });
    }
});

app.delete('/api/administradores/:id', verificarAutenticacao, (req, res) => {
    const adminIdParaExcluir = parseInt(req.params.id);
    const adminLogadoId = req.session.adminId;

    if (adminIdParaExcluir === adminLogadoId) {
        return res.status(400).json({ error: 'Você não pode excluir a sua própria conta enquanto estiver logado nela.' });
    }

    db.get(`SELECT COUNT(*) as count FROM administradores`, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row.count <= 1) {
            return res.status(400).json({ error: 'Não é possível excluir o único administrador restante no sistema.' });
        }

        db.run(`DELETE FROM administradores WHERE id = ?`, [adminIdParaExcluir], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Administrador excluído com sucesso!' });
        });
    });
});

// ================= ROTAS DE GIRAS, HORÁRIOS E AGENDAMENTOS =================

app.get('/api/giras', (req, res) => {
    db.all(`SELECT * FROM giras ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/giras', verificarAutenticacao, (req, res) => {
    const { dia, mes, dia_semana, horario, nome, categoria } = req.body;
    db.run(`INSERT INTO giras (dia, mes, dia_semana, horario, nome, categoria) VALUES (?, ?, ?, ?, ?, ?)`,
        [dia, mes, dia_semana, horario, nome, categoria], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Gira cadastrada com sucesso!', id: this.lastID });
        });
});

app.delete('/api/giras/:id', verificarAutenticacao, (req, res) => {
    db.run(`DELETE FROM giras WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Gira excluída com sucesso!' });
    });
});

app.get('/api/horarios-disponiveis', (req, res) => {
    db.all(`SELECT * FROM horarios WHERE status = 'Disponível' ORDER BY data, horario`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/horarios', verificarAutenticacao, (req, res) => {
    db.all(`SELECT * FROM horarios ORDER BY data DESC, horario DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/horarios', verificarAutenticacao, (req, res) => {
    const { data, horario, servico } = req.body;
    db.run(`INSERT INTO horarios (data, horario, servico, status) VALUES (?, ?, ?, 'Disponível')`,
        [data, horario, servico], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Horário cadastrado com sucesso!', id: this.lastID });
        });
});

app.delete('/api/horarios/:id', verificarAutenticacao, (req, res) => {
    db.run(`DELETE FROM horarios WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Horário excluído com sucesso!' });
    });
});

app.post('/api/agendar', (req, res) => {
    const { nome, telefone, servico, data, horario_id, mensagem } = req.body;
    if (!nome || !telefone || !servico || !data || !horario_id) {
        return res.status(400).json({ error: 'Preencha todos os campos obrigatórios para o agendamento.' });
    }

    db.get(`SELECT * FROM horarios WHERE id = ? AND status = 'Disponível'`, [horario_id], (err, horarioObj) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!horarioObj) return res.status(400).json({ error: 'Este horário não está mais disponível.' });

        db.run(`UPDATE horarios SET status = 'Ocupado' WHERE id = ?`, [horario_id], (err) => {
            if (err) return res.status(500).json({ error: err.message });

            db.run(`INSERT INTO agendamentos (nome, telefone, servico, data, horario_id, horario, mensagem) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [nome, telefone, servico, data, horario_id, horarioObj.horario, mensagem || ''], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ message: 'Consulta agendada com sucesso! Entraremos em contato se necessário.' });
                });
        });
    });
});

app.get('/api/agendamentos', verificarAutenticacao, (req, res) => {
    db.all(`SELECT * FROM agendamentos ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
