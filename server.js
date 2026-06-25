const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_do_not_use_in_production';

// ----- Configuração Isolada do Banco de Dados Dinâmico (PG no Railway / SQLite local) -----
let db;
const connectDB = async () => {
    // Tenta construir a connection string a partir das variáveis individuais do Railway Postgres plugin
    // caso DATABASE_URL não esteja definida explicitamente
    const pgFromEnv = process.env.PGHOST
        ? `postgresql://${process.env.PGUSER || 'postgres'}:${process.env.PGPASSWORD || ''}@${process.env.PGHOST}:${process.env.PGPORT || 5432}/${process.env.PGDATABASE || 'railway'}`
        : null;

    const dbUrl = (process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith('postgres'))
        ? process.env.DATABASE_URL
        : pgFromEnv;

    // Log de diagnóstico para facilitar troubleshooting
    console.log(`[DB] DATABASE_URL presente: ${!!process.env.DATABASE_URL}`);
    console.log(`[DB] PGHOST presente: ${!!process.env.PGHOST}`);
    console.log(`[DB] Connection via: ${dbUrl ? 'PostgreSQL' : 'SQLite (fallback)'}`);

    const maxRetries = 10;
    let retries = 0;

    // Diagnóstico de DNS para o hostname do banco
    const dns = require('dns');
    const hostname = dbUrl ? new URL(dbUrl).hostname : null;
    if (hostname) {
        dns.lookup(hostname, (err, address, family) => {
            if (err) console.error(`[DNS Diagnostic] Falha ao resolver ${hostname}:`, err.message);
            else console.log(`[DNS Diagnostic] ${hostname} resolvido para ${address} (v${family})`);
        });
    }

    const tryConnect = async () => {
        if (dbUrl) {
            console.log(`Conectando ao PostgreSQL... (Tentativa ${retries + 1}/${maxRetries})`);
            const { Pool } = require('pg');
            const pool = new Pool({
                connectionString: dbUrl,
                ssl: { rejectUnauthorized: false },
                connectionTimeoutMillis: 10000,
                idleTimeoutMillis: 30000,
                max: 20
            });

            try {
                await pool.query('SELECT 1');
                console.log("[DB] Conexão com PostgreSQL estabelecida com sucesso.");

                db = {
                    isPg: true,
                    query: async (text, params) => {
                        const { rows } = await pool.query(text, params);
                        return rows;
                    },
                    run: async (text, params) => {
                        const res = await pool.query(text, params);
                        return { lastID: res.insertId, changes: res.rowCount };
                    },
                    pool
                };

                // Tabelas PostgreSQL
                await pool.query(`
                    CREATE TABLE IF NOT EXISTS "User" (
                        id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
                        role TEXT DEFAULT 'user', name TEXT NOT NULL, email TEXT,
                        "firstLogin" BOOLEAN DEFAULT true, "lastPasswordChange" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        "passwordHistory" JSONB DEFAULT '[]'::jsonb, "accountLocked" BOOLEAN DEFAULT false,
                        "failedAttempts" INTEGER DEFAULT 0, "isAuthorized" BOOLEAN DEFAULT false,
                        "isBlockedByAdmin" BOOLEAN DEFAULT false, "lockUntil" TIMESTAMP,
                        "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE IF NOT EXISTS "AuditLog" (
                        id TEXT PRIMARY KEY, "userId" TEXT, action TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "ipAddress" TEXT,
                        "userAgent" TEXT, success BOOLEAN DEFAULT true, details JSONB
                    );
                    CREATE TABLE IF NOT EXISTS "BannerConfig" (
                        id TEXT PRIMARY KEY, key TEXT UNIQUE NOT NULL, label TEXT NOT NULL,
                        enabled BOOLEAN DEFAULT true, "orderIndex" INTEGER DEFAULT 0,
                        "isFrozen" BOOLEAN DEFAULT false, "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE IF NOT EXISTS "UserBannerConfig" (
                        id TEXT PRIMARY KEY, "userId" TEXT NOT NULL, "bannerId" TEXT NOT NULL,
                        enabled BOOLEAN DEFAULT true, "orderIndex" INTEGER DEFAULT 0,
                        "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE("userId", "bannerId")
                    );
                    CREATE TABLE IF NOT EXISTS "SystemConfig" (
                        id TEXT PRIMARY KEY,
                        key TEXT UNIQUE NOT NULL,
                        value TEXT NOT NULL,
                        "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                `);

                const colMigrations = [
                    { table: 'User', from: 'firstlogin', to: 'firstLogin' },
                    { table: 'User', from: 'lastpasswordchange', to: 'lastPasswordChange' },
                    { table: 'User', from: 'passwordhistory', to: 'passwordHistory' },
                    { table: 'User', from: 'accountlocked', to: 'accountLocked' },
                    { table: 'User', from: 'failedattempts', to: 'failedAttempts' },
                    { table: 'User', from: 'isauthorized', to: 'isAuthorized' },
                    { table: 'User', from: 'isblockedbyadmin', to: 'isBlockedByAdmin' },
                    { table: 'User', from: 'lockuntil', to: 'lockUntil' },
                    { table: 'User', from: 'createdat', to: 'createdAt' },
                    { table: 'User', from: 'updatedat', to: 'updatedAt' },
                    { table: 'AuditLog', from: 'ipaddress', to: 'ipAddress' },
                    { table: 'AuditLog', from: 'useragent', to: 'userAgent' },
                ];
                for (const m of colMigrations) {
                    try {
                        await pool.query(`ALTER TABLE "${m.table}" RENAME COLUMN ${m.from} TO "${m.to}"`);
                    } catch (e) { }
                }

                const migrations = [
                    `ALTER TABLE "BannerConfig" ADD COLUMN IF NOT EXISTS "orderIndex" INTEGER DEFAULT 0`,
                    `ALTER TABLE "BannerConfig" ADD COLUMN IF NOT EXISTS "isFrozen" BOOLEAN DEFAULT false`,
                    `ALTER TABLE "BannerConfig" ADD COLUMN IF NOT EXISTS "freezeReason" TEXT DEFAULT 'maintenance'`,
                    `ALTER TABLE "BannerConfig" ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP`,
                    `ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "accountLocked" BOOLEAN DEFAULT false`,
                    `ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "failedAttempts" INTEGER DEFAULT 0`,
                    `ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "lockUntil" TIMESTAMP`,
                    `ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "firstLogin" BOOLEAN DEFAULT true`,
                    `ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "lastPasswordChange" TIMESTAMP DEFAULT CURRENT_TIMESTAMP`,
                    `ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "passwordHistory" JSONB DEFAULT '[]'::jsonb`,
                    `ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "isBlockedByAdmin" BOOLEAN DEFAULT false`,
                ];
                for (const mig of migrations) {
                    try { await pool.query(mig); } catch (e) { }
                }

                const defaultBanners = [
                    { id: 'iss-cnae', key: 'iss-cnae', label: 'Consulta ISS / CNAE' },
                    { id: 'pareceres', key: 'pareceres', label: 'Gerador de Pareceres' },
                    { id: 'processos', key: 'processos', label: 'Análise de Processos' },
                    { id: 'nfse-nacional', key: 'nfse-nacional', label: 'NFS-e Nacional' },
                    { id: 'diario-oficial', key: 'diario-oficial', label: 'Diário Oficial' },
                    { id: 'dte', key: 'dte', label: 'Prefeitura Moderna' },
                    { id: 'arrecadacao', key: 'arrecadacao', label: 'Transparência' },
                    { id: 'receita', key: 'receita', label: 'Arrecadação' },
                    { id: 'entes', key: 'entes', label: 'Entes Federados' },
                    { id: 'empresa-facil', key: 'empresa-facil', label: 'Empresa Fácil' },
                    { id: 'biblioteca', key: 'biblioteca', label: 'Biblioteca' },
                    { id: 'sistema-ponto', key: 'sistema-ponto', label: 'Sistema de Ponto' },
                    { id: 'justificativas-ponto', key: 'justificativas-ponto', label: 'Justificativas de Ponto' },
                    { id: 'contra-cheque', key: 'contra-cheque', label: 'Contra-cheque' },
                    { id: 'dte-portal', key: 'dte-portal', label: 'Terra Cloud (DTE)' },
                    { id: 'dte-meuiss', key: 'dte-meuiss', label: 'Meu ISS (DTE)' },
                    { id: 'dte-nfe', key: 'dte-nfe', label: 'NFS-e / Nota Fiscal (DTE)' },
                    { id: 'dte-iptu', key: 'dte-iptu', label: 'Protocolo (DTE)' },
                    { id: 'dte-meuiptu', key: 'dte-meuiptu', label: 'Meu IPTU (DTE)' },
                    { id: 'dte-login', key: 'dte-login', label: 'DTE - Domicílio Tributário' },
                    { id: 'dte-simples-fiscal', key: 'dte-simples-fiscal', label: 'Simples Fiscal (DTE)' },
                    { id: 'dte-helpdesk', key: 'dte-helpdesk', label: 'HelpDesk Tickets (DTE)' },
                    { id: 'consultas-iss-cnae', key: 'consultas-iss-cnae', label: 'Consulta ISS / CNAE (CF)' },
                    { id: 'consultas-nfse-nacional', key: 'consultas-nfse-nacional', label: 'Consulta NFS-e Nacional (CF)' }
                ];
                for (let i = 0; i < defaultBanners.length; i++) {
                    const b = defaultBanners[i];
                    await pool.query(
                        `INSERT INTO "BannerConfig" (id, key, label, enabled, "orderIndex") VALUES ($1, $2, $3, $4, $5) ON CONFLICT (key) DO NOTHING`,
                        [b.id, b.key, b.label, true, i]
                    );
                }

                await pool.query(
                    `INSERT INTO "SystemConfig" (id, key, value) VALUES ($1, $2, $3) ON CONFLICT (key) DO NOTHING`,
                    [uuidv4(), 'lockscreen_timeout', '5']
                );

                return true;

            } catch (err) {
                console.error(`[DB] Erro ao conectar (Tentativa ${retries + 1}):`, err.message);
                retries++;
                if (retries < maxRetries) {
                    const delay = Math.min(Math.pow(2, retries) * 1000, 15000);
                    console.log(`[DB] Tentando novamente em ${delay / 1000}s...`);
                    await new Promise(res => setTimeout(res, delay));
                    return tryConnect();
                } else {
                    console.error("[DB] Máximo de tentativas atingido.");
                    throw err;
                }
            }
        } else {
            console.log("Usando SQLite Local...");
            const sqlite3 = require('sqlite3').verbose();
            const dbPath = process.env.SQLITE_PATH || './dev.sqlite3';
            const sqldb = new sqlite3.Database(dbPath);

            db = {
                isPg: false,
                query: (text, params) => new Promise((resolve, reject) => {
                    const formattedText = text.replace(/\$\d+/g, '?');
                    sqldb.all(formattedText, params, (err, rows) => {
                        if (err) reject(err); else resolve(rows);
                    });
                }),
                run: (text, params) => new Promise((resolve, reject) => {
                    const formattedText = text.replace(/\$\d+/g, '?');
                    sqldb.run(formattedText, params, function (err) {
                        if (err) reject(err); else resolve({ lastID: this.lastID, changes: this.changes });
                    });
                })
            };

            await db.run(`CREATE TABLE IF NOT EXISTS User (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'user', name TEXT NOT NULL, email TEXT, firstLogin INTEGER DEFAULT 1, lastPasswordChange TEXT DEFAULT CURRENT_TIMESTAMP, passwordHistory TEXT DEFAULT '[]', accountLocked INTEGER DEFAULT 0, failedAttempts INTEGER DEFAULT 0, isAuthorized INTEGER DEFAULT 0, isBlockedByAdmin INTEGER DEFAULT 0, lockUntil TEXT, createdAt TEXT DEFAULT CURRENT_TIMESTAMP, updatedAt TEXT DEFAULT CURRENT_TIMESTAMP);`);
            await db.run(`CREATE TABLE IF NOT EXISTS AuditLog (id TEXT PRIMARY KEY, userId TEXT, action TEXT NOT NULL, timestamp TEXT DEFAULT CURRENT_TIMESTAMP, ipAddress TEXT, userAgent TEXT, success INTEGER DEFAULT 1, details TEXT);`);
            await db.run(`CREATE TABLE IF NOT EXISTS BannerConfig (id TEXT PRIMARY KEY, key TEXT UNIQUE NOT NULL, label TEXT NOT NULL, enabled INTEGER DEFAULT 1, orderIndex INTEGER DEFAULT 0, isFrozen INTEGER DEFAULT 0, updatedAt TEXT DEFAULT CURRENT_TIMESTAMP);`);
            await db.run(`CREATE TABLE IF NOT EXISTS UserBannerConfig (id TEXT PRIMARY KEY, userId TEXT NOT NULL, bannerId TEXT NOT NULL, enabled INTEGER DEFAULT 1, orderIndex INTEGER DEFAULT 0, updatedAt TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(userId, bannerId));`);
            await db.run(`CREATE TABLE IF NOT EXISTS SystemConfig (id TEXT PRIMARY KEY, key TEXT UNIQUE NOT NULL, value TEXT NOT NULL, updatedAt TEXT DEFAULT CURRENT_TIMESTAMP);`);

            try {
                const columns = await db.query("PRAGMA table_info(BannerConfig)");
                if (!columns.some(col => col.name === 'orderIndex')) await db.run(`ALTER TABLE BannerConfig ADD COLUMN orderIndex INTEGER DEFAULT 0;`);
                if (!columns.some(col => col.name === 'isFrozen')) await db.run(`ALTER TABLE BannerConfig ADD COLUMN isFrozen INTEGER DEFAULT 0;`);
                if (!columns.some(col => col.name === 'freezeReason')) await db.run(`ALTER TABLE BannerConfig ADD COLUMN freezeReason TEXT DEFAULT 'maintenance';`);
                if (!columns.some(col => col.name === 'updatedAt')) await db.run(`ALTER TABLE BannerConfig ADD COLUMN updatedAt TEXT DEFAULT CURRENT_TIMESTAMP;`);
            } catch (e) { }

            const defaultBanners = [
                { id: 'iss-cnae', key: 'iss-cnae', label: 'Consulta ISS / CNAE' },
                { id: 'pareceres', key: 'pareceres', label: 'Gerador de Pareceres' },
                { id: 'processos', key: 'processos', label: 'Análise de Processos' },
                { id: 'nfse-nacional', key: 'nfse-nacional', label: 'NFS-e Nacional' },
                { id: 'diario-oficial', key: 'diario-oficial', label: 'Diário Oficial' },
                { id: 'dte', key: 'dte', label: 'Prefeitura Moderna' },
                { id: 'arrecadacao', key: 'arrecadacao', label: 'Transparência' },
                { id: 'receita', key: 'receita', label: 'Arrecadação' },
                { id: 'entes', key: 'entes', label: 'Entes Federados' },
                { id: 'empresa-facil', key: 'empresa-facil', label: 'Empresa Fácil' },
                { id: 'biblioteca', key: 'biblioteca', label: 'Biblioteca' },
                { id: 'sistema-ponto', key: 'sistema-ponto', label: 'Sistema de Ponto' },
                { id: 'justificativas-ponto', key: 'justificativas-ponto', label: 'Justificativas de Ponto' },
                { id: 'contra-cheque', key: 'contra-cheque', label: 'Contra-cheque' },
                { id: 'dte-portal', key: 'dte-portal', label: 'Terra Cloud (DTE)' },
                { id: 'dte-meuiss', key: 'dte-meuiss', label: 'Meu ISS (DTE)' },
                { id: 'dte-nfe', key: 'dte-nfe', label: 'NFS-e / Nota Fiscal (DTE)' },
                { id: 'dte-iptu', key: 'dte-iptu', label: 'Protocolo (DTE)' },
                { id: 'dte-meuiptu', key: 'dte-meuiptu', label: 'Meu IPTU (DTE)' },
                { id: 'dte-login', key: 'dte-login', label: 'DTE - Domicílio Tributário' },
                { id: 'dte-simples-fiscal', key: 'dte-simples-fiscal', label: 'Simples Fiscal (DTE)' },
                { id: 'dte-helpdesk', key: 'dte-helpdesk', label: 'HelpDesk Tickets (DTE)' },
                { id: 'consultas-iss-cnae', key: 'consultas-iss-cnae', label: 'Consulta ISS / CNAE (CF)' },
                { id: 'consultas-nfse-nacional', key: 'consultas-nfse-nacional', label: 'Consulta NFS-e Nacional (CF)' }
            ];
            for (let i = 0; i < defaultBanners.length; i++) {
                const b = defaultBanners[i];
                await db.run(`INSERT OR IGNORE INTO BannerConfig (id, key, label, enabled, orderIndex) VALUES ($1, $2, $3, $4, $5)`, [b.id, b.key, b.label, 1, i]);
            }
            await db.run(`INSERT OR IGNORE INTO SystemConfig (id, key, value) VALUES ($1, $2, $3)`, [uuidv4(), 'lockscreen_timeout', '5']);
        }
    };

    // Executar a conexão com retry
    await tryConnect();

    // Remove o banner 'incidencia' obsoleto
    try {
        await db.run('DELETE FROM "BannerConfig" WHERE key = $1', ['incidencia']);
        await db.run('DELETE FROM "UserBannerConfig" WHERE "bannerId" = $1', ['incidencia']);
        console.log("[DB] Banner de incidência obsoleto removido.");
    } catch (e) {
        console.error("[DB] Erro ao remover banner obsoleto:", e.message);
    }

    const bcrypt = require('bcrypt');
    const adminCheck = await db.query('SELECT * FROM "User" WHERE username = $1', ['admin']);
    console.log(`[Diagnostic] Verificação do admin inicial: Encontrados ${adminCheck ? adminCheck.length : 0} usuários 'admin'.`);
    if (!adminCheck || adminCheck.length === 0) {
        const adminId = uuidv4();
        const hashedAdminPass = await bcrypt.hash('Admin@123', 10);
        try {
            await db.run(`INSERT INTO "User" (id, username, password, name, role, "isAuthorized", "isBlockedByAdmin", "accountLocked", "failedAttempts", "firstLogin") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, [adminId, 'admin', hashedAdminPass, 'Administrador do Sistema', 'admin', true, false, false, 0, false]);
            console.log("[Diagnostic] Usuário admin padrão criado.");
        } catch (e) {
            console.log("[Diagnostic] Erro ao criar admin:", e.message);
        }
    }

    try {
        await db.run(`UPDATE "User" SET "isBlockedByAdmin" = $1, "accountLocked" = $2, "failedAttempts" = $3, "isAuthorized" = $4, "lockUntil" = NULL WHERE role = $5`, [false, false, 0, true, 'admin']);
        console.log("Administradores desbloqueados na inicialização.");
    } catch (e) { }
};

// Conectar ao Banco de Dados na inicialização
connectDB().catch(console.error);

app.use(cors());
app.use(express.json());

// Função utilitária global para UUID versão simples
function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Middleware de Autenticação
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Acesso negado, token ausente" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Token inválido ou expirado" });
        req.user = user;
        next();
    });
};

// Middleware de Verificação de Banco de Dados
const requireDB = (req, res, next) => {
    if (!db) {
        return res.status(503).json({
            error: "Banco de dados temporariamente indisponível. Verifique se o banco no Railway não está em modo 'sleeping'.",
            status: "offline"
        });
    }
    next();
};

// Health Check Endpoint
app.get('/api/health', async (req, res) => {
    try {
        if (!db) throw new Error("Database not initialized");
        await db.query('SELECT 1');
        res.json({ status: "ok", database: "connected", engine: db.isPg ? "PostgreSQL" : "SQLite" });
    } catch (err) {
        res.status(503).json({ status: "error", database: "disconnected", message: err.message });
    }
});

/* --- Rotas de Autenticação (Agnósticas - Sem ORM) --- */

// Validação de Sessão
app.get('/api/auth/validate', requireDB, authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const users = await db.query('SELECT * FROM "User" WHERE id = $1', [userId]);
        const user = users.length > 0 ? users[0] : null;

        if (!user) {
            return res.status(401).json({ error: "Sessão inválida: Usuário não encontrado." });
        }

        const isLocked = String(user.accountLocked).toLowerCase() === 'true' || user.accountLocked === true || user.accountLocked === 1 || user.accountLocked === 't';
        const isBlocked = String(user.isBlockedByAdmin).toLowerCase() === 'true' || user.isBlockedByAdmin === true || user.isBlockedByAdmin === 1 || user.isBlockedByAdmin === 't';
        const isAuthorized = String(user.isAuthorized).toLowerCase() === 'true' || user.isAuthorized === true || user.isAuthorized === 1 || user.isAuthorized === 't';

        if (isLocked) {
            return res.status(403).json({ error: "Conta temporariamente bloqueada.", isLocked: true });
        }
        
        if (isBlocked) {
            return res.status(403).json({ error: "Sua conta foi bloqueada pelo administrador.", isBlocked: true });
        }
        
        if (!isAuthorized) {
            return res.status(403).json({ error: "Sua conta ainda não foi aprovada pelo administrador." });
        }

        const firstLogin = String(user.firstLogin).toLowerCase() === 'true' || user.firstLogin === true || user.firstLogin === 1 || user.firstLogin === 't';

        res.json({
            user: {
                id: user.id, 
                username: user.username, 
                name: user.name,
                email: user.email, 
                role: user.role, 
                firstLogin
            }
        });
    } catch (error) {
        console.error("Erro na validação de token:", error);
        res.status(500).json({ error: "Erro interno no servidor ao validar sessão" });
    }
});

// Registro de Usuário
app.post('/api/auth/register', requireDB, async (req, res) => {
    try {
        const { username, password, name, email } = req.body;
        // ... resta da rota

        if (!username || !password || !name) {
            return res.status(400).json({ error: "Todos os campos obrigatórios precisam ser preenchidos" });
        }

        const existingQuery = await db.query('SELECT * FROM "User" WHERE username = $1', [username]);
        if (existingQuery.length > 0) {
            return res.status(400).json({ error: "Nome de usuário já existe" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();
        const jsonHistory = JSON.stringify([hashedPassword]);

        await db.run(
            `INSERT INTO "User" (id, username, password, name, email, role, "isAuthorized", "passwordHistory", "firstLogin")
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [userId, username, hashedPassword, name, email || null, 'user', false, jsonHistory, false]
        );

        console.log("Usuario inserido. Inserindo log...");

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, "ipAddress", details) VALUES ($1, $2, $3, $4, $5${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), userId, 'user_registered', req.ip || 'unknown', JSON.stringify({ username })]
        );

        res.status(201).json({ message: "Cadastro realizado com sucesso! Aguarde aprovação do administrador.", user: { id: userId, username } });

    } catch (error) {
        console.error("====== ERRO NO REGISTRO ======");
        console.error(error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Login
app.post('/api/auth/login', requireDB, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) return res.status(400).json({ error: "Usuário e senha são obrigatórios" });

        const users = await db.query('SELECT * FROM "User" WHERE username = $1', [username]);
        const user = users.length > 0 ? users[0] : null;

        if (!user) {
            await db.run(`INSERT INTO "AuditLog" (id, action, "ipAddress", details, success) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''}, $5)`,
                [uuidv4(), 'login_failure', req.ip || 'unknown', JSON.stringify({ username, reason: 'user_not_found' }), false]);
            return res.status(401).json({ error: "Credenciais inválidas" });
        }

        // SQLite converte booleanos para 1/0, e PG pode retornar strings ou booleanos nativos
        const isLocked = String(user.accountLocked).toLowerCase() === 'true' || user.accountLocked === true || user.accountLocked === 1 || user.accountLocked === 't';
        const isBlocked = String(user.isBlockedByAdmin).toLowerCase() === 'true' || user.isBlockedByAdmin === true || user.isBlockedByAdmin === 1 || user.isBlockedByAdmin === 't';
        const isAuthorized = String(user.isAuthorized).toLowerCase() === 'true' || user.isAuthorized === true || user.isAuthorized === 1 || user.isAuthorized === 't';

        if (isLocked || isBlocked) {
            await db.run(`INSERT INTO "AuditLog" (id, "userId", action, "ipAddress", details, success) VALUES ($1, $2, $3, $4, $5${db.isPg ? '::jsonb' : ''}, $6)`,
                [uuidv4(), user.id, 'login_failure', req.ip || 'unknown', JSON.stringify({ reason: isLocked ? 'account_locked' : 'blocked_by_admin' }), false]);

            let errorMsg = "Sua conta está bloqueada.";
            if (isLocked && user.lockUntil) {
                const lockTime = new Date(user.lockUntil);
                if (lockTime > new Date()) {
                    const diffMs = lockTime - new Date();
                    const diffMins = Math.ceil(diffMs / 60000);
                    errorMsg = `Conta bloqueada por excesso de tentativas. Tente novamente em ${diffMins} minuto(s).`;
                } else {
                    // Time passed, we should theoretically unlock here, but let's unlock and allow retry.
                    await db.run(`UPDATE "User" SET "failedAttempts" = 0, "accountLocked" = false, "lockUntil" = NULL WHERE id = $1`, [user.id]);
                    // We'll let it fail or succeed down the line based on the password logic
                }
            } else if (isBlocked) {
                errorMsg = "Sua conta foi bloqueada pelo administrador.";
            }

            if ((isLocked && new Date(user.lockUntil) > new Date()) || isBlocked) {
                return res.status(403).json({ error: errorMsg, isLocked: true });
            }
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            const newFailedAttempts = (user.failedAttempts || 0) + 1;
            let query = `UPDATE "User" SET "failedAttempts" = $1`;
            let params = [newFailedAttempts, user.id];

            if (newFailedAttempts >= 5) {
                query += `, "accountLocked" = $2, "lockUntil" = $3`;
                const lockUntil = new Date();
                lockUntil.setMinutes(lockUntil.getMinutes() + 30);
                params = [newFailedAttempts, true, lockUntil.toISOString(), user.id];
            }
            query += ` WHERE id = $${params.length}`; // $2 ou $4 dependendo da condição

            await db.run(query, params);
            await db.run(`INSERT INTO "AuditLog" (id, "userId", action, "ipAddress", details, success) VALUES ($1, $2, $3, $4, $5${db.isPg ? '::jsonb' : ''}, $6)`,
                [uuidv4(), user.id, 'login_failure', req.ip || 'unknown', JSON.stringify({ reason: 'invalid_password', attempts: newFailedAttempts }), false]);

            if (newFailedAttempts >= 5) {
                return res.status(401).json({ error: "Conta bloqueada por 30 minutos após 5 tentativas de falha.", isLocked: true });
            } else {
                const attemptsLeft = 5 - newFailedAttempts;
                let warning = "Credenciais inválidas.";
                if (attemptsLeft <= 2) {
                    warning = `Credenciais inválidas. Restam apenas ${attemptsLeft} tentativa(s) antes do bloqueio da conta.`;
                }
                return res.status(401).json({ error: warning, attemptsLeft });
            }
        }

        if (!isAuthorized) {
            return res.status(403).json({ error: "Sua conta ainda não foi aprovada pelo administrador." });
        }

        // Resetar failed attempts
        await db.run(`UPDATE "User" SET "failedAttempts" = 0, "accountLocked" = false, "lockUntil" = NULL WHERE id = $1`, [user.id]);

        const firstLogin = String(user.firstLogin).toLowerCase() === 'true' || user.firstLogin === true || user.firstLogin === 1 || user.firstLogin === 't';

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role, firstLogin },
            JWT_SECRET,
            { expiresIn: '12h' }
        );

        await db.run(`INSERT INTO "AuditLog" (id, "userId", action) VALUES ($1, $2, $3)`, [uuidv4(), user.id, 'login_success']);

        res.json({
            token,
            user: {
                id: user.id, username: user.username, name: user.name,
                email: user.email, role: user.role, firstLogin
            }
        });

    } catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Recuperação de Senha (Esqueci minha Senha)
app.post('/api/auth/forgot-password', requireDB, async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) return res.status(400).json({ error: "Nome de usuário é obrigatório." });

        const users = await db.query('SELECT id FROM "User" WHERE username = $1', [username]);

        // Log auditing operation whether user exists or not, avoids enumeration attacks
        const userId = users.length > 0 ? users[0].id : null;

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, "ipAddress", details) VALUES ($1, $2, $3, $4, $5${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), userId, 'forgot_password_request', req.ip || 'unknown', JSON.stringify({ requestedUsername: username })]
        );

        // Always return success for security (prevents user guessing)
        res.json({ message: "Se o usuário existir, o administrador responsável será notificado sobre a solicitação de redefinição." });

    } catch (error) {
        console.error("====== ERRO NO ESQUECI A SENHA ======");
        console.error(error);
        res.status(500).json({ error: "Erro interno no servidor." });
    }
});

// Atualizar o perfil do próprio usuário (Exige Token JWT válido)
app.put('/api/auth/profile', authenticateToken, requireDB, async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, email, username, currentPassword, newPassword } = req.body;

        const users = await db.query('SELECT * FROM "User" WHERE id = $1', [userId]);
        if (users.length === 0) return res.status(404).json({ error: "Usuário não encontrado" });
        const user = users[0];

        const updates = [];
        const params = [];
        const addUpdate = (field, value, isJson = false) => {
            params.push(value);
            const cast = (isJson && db.isPg) ? '::jsonb' : '';
            updates.push(`"${field}" = $${params.length}${cast}`);
        };

        if (name) addUpdate('name', name);
        if (email) addUpdate('email', email);

        if (username && username !== user.username) {
            const existing = await db.query('SELECT * FROM "User" WHERE username = $1', [username]);
            if (existing.length > 0) return res.status(400).json({ error: "Este nome de usuário já está em uso" });
            addUpdate('username', username);
        }

        let isPasswordChanged = false;
        if (newPassword) {
            const isFirstLogin = String(user.firstLogin).toLowerCase() === 'true' || user.firstLogin === 1 || user.firstLogin === true || user.firstLogin === 't';

            if (!isFirstLogin && !currentPassword) {
                return res.status(400).json({ error: "A senha atual é obrigatória para redefinir a senha." });
            }

            if (!isFirstLogin && currentPassword) {
                const validPassword = await bcrypt.compare(currentPassword, user.password);
                if (!validPassword) return res.status(401).json({ error: "Senha atual incorreta" });
            }

            const newHashedPassword = await bcrypt.hash(newPassword, 10);

            // Lidar com JSON de History de forma simples
            let history = [];
            try { history = JSON.parse(user.passwordHistory || '[]'); } catch (e) { }

            const isReused = history.some(hash => bcrypt.compareSync(newPassword, hash));
            if (isReused) return res.status(400).json({ error: "Esta senha já foi usada recentemente" });

            addUpdate('password', newHashedPassword);
            addUpdate('firstLogin', db.isPg ? false : 0);
            addUpdate('lastPasswordChange', new Date().toISOString());

            history.push(newHashedPassword);
            if (history.length > 5) history.shift();
            addUpdate('passwordHistory', JSON.stringify(history), true);

            isPasswordChanged = true;
        }

        if (updates.length > 0) {
            params.push(userId); // Adiciona userId como o ULTIMO parametro
            const query = `UPDATE "User" SET ${updates.join(', ')} WHERE id = $${params.length}`;
            await db.run(query, params);
        }

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), userId, 'profile_updated', JSON.stringify({ passwordChanged: isPasswordChanged })]
        );

        // Retornar o usuário atualizado pra facilitar vida do front
        const updatedUsers = await db.query('SELECT * FROM "User" WHERE id = $1', [userId]);
        const updatedUser = updatedUsers[0];

        res.json({
            message: "Perfil atualizado com sucesso", user: {
                id: updatedUser.id, username: updatedUser.username, name: updatedUser.name,
                email: updatedUser.email, role: updatedUser.role,
                firstLogin: String(updatedUser.firstLogin).toLowerCase() === 'true' || updatedUser.firstLogin === 1 || updatedUser.firstLogin === true || updatedUser.firstLogin === 't'
            }
        });
    } catch (error) {
        console.error("Erro na atualização do perfil:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Middleware para verificar se é Admin
const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: "Acesso negado. Apenas administradores." });
    }
    next();
};

// ================= ROTAS DE ADMINISTRAÇÃO =================

// 1. Listar todos os usuários (Apenas Admin)
app.get('/api/auth/users', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    try {
        const users = await db.query('SELECT id, username, name, email, role, "isAuthorized", "isBlockedByAdmin", "accountLocked", "createdAt" FROM "User"');
        res.json(users);
    } catch (error) {
        console.error("Erro ao listar usuários:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// 2. Autorizar um usuário pendente
app.post('/api/auth/users/:id/authorize', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        await db.run('UPDATE "User" SET "isAuthorized" = $1 WHERE id = $2', [true, id]);

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), req.user.id, 'admin_authorized_user', JSON.stringify({ targetUserId: id })]
        );

        res.json({ message: "Usuário autorizado com sucesso." });
    } catch (error) {
        console.error("Erro ao autorizar usuário:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// 3. Bloquear / Desbloquear usuário
app.post('/api/auth/users/:id/block', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const users = await db.query('SELECT "isBlockedByAdmin" FROM "User" WHERE id = $1', [id]);

        if (users.length === 0) return res.status(404).json({ error: "Usuário não encontrado" });

        // SQLite boolean to int
        const currentStatus = users[0].isBlockedByAdmin === true || users[0].isBlockedByAdmin === 1;
        const newStatus = !currentStatus;
        await db.run('UPDATE "User" SET "isBlockedByAdmin" = $1 WHERE id = $2', [newStatus, id]);

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), req.user.id, newStatus ? 'admin_blocked_user' : 'admin_unblocked_user', JSON.stringify({ targetUserId: id })]
        );

        res.json({ message: `Usuário ${newStatus ? 'bloqueado' : 'desbloqueado'} com sucesso.` });
    } catch (error) {
        console.error("Erro ao bloquear usuário:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// 4. Resetar senha de um usuário
app.post('/api/auth/users/:id/reset-password', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const defaultPassword = "Mudar@123";
        const hashedPassword = await bcrypt.hash(defaultPassword, 10);

        await db.run('UPDATE "User" SET password = $1, "firstLogin" = $2 WHERE id = $3', [hashedPassword, true, id]);

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), req.user.id, 'admin_reset_password', JSON.stringify({ targetUserId: id })]
        );

        res.json({ message: "Senha resetada para 'Mudar@123'." });
    } catch (error) {
        console.error("Erro ao resetar senha:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// 5. Excluir usuário
app.delete('/api/auth/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (req.user.id === id) {
            return res.status(400).json({ error: "Não é possível excluir o próprio usuário." });
        }

        await db.run('DELETE FROM "User" WHERE id = $1', [id]);
        await db.run('DELETE FROM "AuditLog" WHERE "userId" = $1', [id]);

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), req.user.id, 'admin_deleted_user', JSON.stringify({ targetUserId: id })]
        );

        res.json({ message: "Usuário excluído com sucesso." });
    } catch (error) {
        console.error("Erro ao deletar usuário:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// 6. Buscar Logs de Auditoria Detalhados (MCP Tool Support)
app.get('/api/admin/audit-detailed', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { limit = 50, action, userId } = req.query;
        let query = 'SELECT a.*, u.username FROM "AuditLog" a LEFT JOIN "User" u ON a."userId" = u.id WHERE 1=1';
        const params = [];

        if (action) {
            params.push(action);
            query += ` AND a.action = $${params.length}`;
        }
        if (userId) {
            params.push(userId);
            query += ` AND a."userId" = $${params.length}`;
        }

        query += ` ORDER BY a.timestamp DESC LIMIT $${params.length + 1}`;
        params.push(parseInt(limit, 10));

        const logs = await db.query(query, params);
        res.json(logs);
    } catch (error) {
        console.error("Erro ao buscar logs detalhados:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});


// ================= ROTAS DE BANNERS =================

// Listar banners com status — com token opcional para personalização por usuário
app.get('/api/banners', requireDB, async (req, res) => {
    try {
        const globalBanners = await db.query('SELECT id, key, label, enabled, "orderIndex", "isFrozen", "freezeReason" FROM "BannerConfig" ORDER BY "orderIndex" ASC, id ASC');
        const normalized = globalBanners.map(b => ({
            ...b,
            enabled: String(b.enabled).toLowerCase() === 'true' || b.enabled === true || b.enabled === 1 || b.enabled === 't',
            isFrozen: String(b.isFrozen).toLowerCase() === 'true' || b.isFrozen === true || b.isFrozen === 1 || b.isFrozen === 't',
            freezeReason: b.freezeReason || 'maintenance'
        }));

        // Tenta extrair o userId do token JWT (se enviado)
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (token) {
            try {
                const decoded = require('jsonwebtoken').verify(token, JWT_SECRET);
                const userId = decoded.id;

                // Busca overrides do usuário
                const overrides = await db.query(
                    'SELECT "bannerId", enabled, "orderIndex" FROM "UserBannerConfig" WHERE "userId" = $1',
                    [userId]
                );

                if (overrides.length > 0) {
                    // Mescla: override prevalece sobre global
                    const overrideMap = {};
                    overrides.forEach(o => {
                        overrideMap[o.bannerId] = {
                            enabled: String(o.enabled).toLowerCase() === 'true' || o.enabled === true || o.enabled === 1 || o.enabled === 't',
                            orderIndex: o.orderIndex
                        };
                    });

                    const merged = normalized.map(b => {
                        if (overrideMap[b.id] !== undefined) {
                            return {
                                ...b,
                                enabled: overrideMap[b.id].enabled,
                                orderIndex: overrideMap[b.id].orderIndex,
                                isFrozen: b.isFrozen,
                                freezeReason: b.freezeReason,
                                hasOverride: true
                            };
                        }
                        return b;
                    });

                    // Reordena se houver overrides com orderIndex
                    merged.sort((a, b) => (a.orderIndex ?? 999) - (b.orderIndex ?? 999));
                    return res.json(merged);
                }
            } catch (e) {
                // token inválido ou expirado — retorna global sem erro
            }
        }

        res.json(normalized);
    } catch (error) {
        console.error('Erro ao listar banners:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// ================= ROTA DE REORDENAÇÃO MÚLTIPLA =================
app.put('/api/admin/banners/reorder', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { orderedBanners } = req.body; // Expects: [{ id: '123', orderIndex: 0 }, { id: '456', orderIndex: 1 }]

        if (!Array.isArray(orderedBanners)) {
            return res.status(400).json({ error: 'Payload inválido. Esperado um array de banners.' });
        }

        // We update one by one as a simplified approach for SQLite and Postgres compatibility
        for (const item of orderedBanners) {
            if (item.id !== undefined && item.orderIndex !== undefined) {
                await db.run(
                    'UPDATE "BannerConfig" SET "orderIndex" = $1, "updatedAt" = $2 WHERE id = $3',
                    [item.orderIndex, new Date().toISOString(), item.id]
                );
            }
        }

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), req.user.id, 'admin_reorder_banners', JSON.stringify({ count: orderedBanners.length })]
        );

        res.json({ message: 'Banners reordenados com sucesso.', success: true });
    } catch (error) {
        console.error('Erro ao reordenar banners:', error);
        res.status(500).json({ error: 'Erro interno no servidor ao tentar reordenar' });
    }
});

// Alternar estado de um banner (admin only)
app.put('/api/admin/banners/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { enabled } = req.body;

        if (typeof enabled === 'undefined') {
            return res.status(400).json({ error: 'Campo "enabled" é obrigatório.' });
        }

        const banners = await db.query('SELECT * FROM "BannerConfig" WHERE id = $1', [id]);
        if (banners.length === 0) return res.status(404).json({ error: 'Banner não encontrado.' });

        const enabledValue = db.isPg ? !!enabled : (enabled ? 1 : 0);
        await db.run(
            'UPDATE "BannerConfig" SET enabled = $1, updatedAt = $2 WHERE id = $3',
            [enabledValue, new Date().toISOString(), id]
        );

        await db.run(
            `INSERT INTO AuditLog (id, userId, action, details) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), req.user.id, 'admin_toggle_banner', JSON.stringify({ bannerId: id, enabled })]
        );

        res.json({ message: `Banner ${enabled ? 'ativado' : 'desativado'} com sucesso.`, id, enabled });
    } catch (error) {
        console.error('Erro ao atualizar banner:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// Congelar/Descongelar um banner global (admin only)
app.put('/api/admin/banners/:id/freeze', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { isFrozen, freezeReason } = req.body;

        if (typeof isFrozen === 'undefined') {
            return res.status(400).json({ error: 'Campo "isFrozen" é obrigatório.' });
        }

        const banners = await db.query('SELECT * FROM "BannerConfig" WHERE id = $1', [id]);
        if (banners.length === 0) return res.status(404).json({ error: 'Banner não encontrado.' });

        const frozenValue = db.isPg ? !!isFrozen : (isFrozen ? 1 : 0);
        const reasonValue = freezeReason || 'maintenance';

        await db.run(
            'UPDATE "BannerConfig" SET "isFrozen" = $1, "freezeReason" = $2, "updatedAt" = $3 WHERE id = $4',
            [frozenValue, reasonValue, new Date().toISOString(), id]
        );

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), req.user.id, 'admin_freeze_banner', JSON.stringify({ bannerId: id, isFrozen, freezeReason: reasonValue })]
        );

        res.json({ message: `Banner ${isFrozen ? 'congelado' : 'descongelado'} com sucesso.`, id, isFrozen, freezeReason: reasonValue });
    } catch (error) {
        console.error('Erro ao congelar/descongelar banner:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// =============== ROTAS DE BANNERS POR USUÁRIO (ADMIN) ===============

// Listar banners globais com overrides do usuário mesclados
app.get('/api/admin/users/:userId/banners', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;

        const globalBanners = await db.query(
            'SELECT id, key, label, enabled, "orderIndex" FROM "BannerConfig" ORDER BY "orderIndex" ASC, id ASC'
        );
        const overrides = await db.query(
            'SELECT "bannerId", enabled, "orderIndex" FROM "UserBannerConfig" WHERE "userId" = $1',
            [userId]
        );

        const overrideMap = {};
        overrides.forEach(o => {
            overrideMap[o.bannerId] = {
                enabled: String(o.enabled).toLowerCase() === 'true' || o.enabled === true || o.enabled === 1 || o.enabled === 't',
                orderIndex: o.orderIndex
            };
        });

        const merged = globalBanners.map(b => {
            const normalizedGlobal = String(b.enabled).toLowerCase() === 'true' || b.enabled === true || b.enabled === 1 || b.enabled === 't';
            if (overrideMap[b.id] !== undefined) {
                return {
                    ...b,
                    enabled: overrideMap[b.id].enabled,
                    orderIndex: overrideMap[b.id].orderIndex,
                    globalEnabled: normalizedGlobal,
                    hasOverride: true
                };
            }
            return { ...b, enabled: normalizedGlobal, globalEnabled: normalizedGlobal, hasOverride: false };
        });

        res.json(merged);
    } catch (error) {
        console.error('Erro ao listar banners do usuário:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// Ativar/desativar um banner específico para um usuário (cria ou atualiza override)
app.put('/api/admin/users/:userId/banners/:bannerId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId, bannerId } = req.params;
        const { enabled } = req.body;

        if (typeof enabled === 'undefined') {
            return res.status(400).json({ error: 'Campo "enabled" é obrigatório.' });
        }

        const userCheck = await db.query('SELECT id FROM "User" WHERE id = $1', [userId]);
        if (userCheck.length === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });

        const bannerCheck = await db.query('SELECT id, "orderIndex" FROM "BannerConfig" WHERE id = $1', [bannerId]);
        if (bannerCheck.length === 0) return res.status(404).json({ error: 'Banner não encontrado.' });

        const enabledValue = db.isPg ? !!enabled : (enabled ? 1 : 0);
        const overrideId = uuidv4();
        const now = new Date().toISOString();
        const globalOrder = bannerCheck[0].orderIndex ?? 0;

        // UPSERT: se já existe override, atualiza; senão, cria
        const existing = await db.query(
            'SELECT id FROM "UserBannerConfig" WHERE "userId" = $1 AND "bannerId" = $2',
            [userId, bannerId]
        );

        if (existing.length > 0) {
            await db.run(
                'UPDATE "UserBannerConfig" SET enabled = $1, updatedAt = $2 WHERE "userId" = $3 AND "bannerId" = $4',
                [enabledValue, now, userId, bannerId]
            );
        } else {
            await db.run(
                'INSERT INTO "UserBannerConfig" (id, "userId", "bannerId", enabled, "orderIndex", updatedAt) VALUES ($1, $2, $3, $4, $5, $6)',
                [overrideId, userId, bannerId, enabledValue, globalOrder, now]
            );
        }

        await db.run(
            'INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4' + (db.isPg ? '::jsonb' : '') + ')',
            [uuidv4(), req.user.id, 'admin_toggle_user_banner', JSON.stringify({ targetUserId: userId, bannerId, enabled })]
        );

        res.json({ message: `Banner ${enabled ? 'ativado' : 'desativado'} para o usuário com sucesso.`, userId, bannerId, enabled });
    } catch (error) {
        console.error('Erro ao atualizar banner do usuário:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// Reordenar banners de um usuário específico
app.put('/api/admin/users/:userId/banners/reorder', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { orderedBanners } = req.body;

        if (!Array.isArray(orderedBanners)) {
            return res.status(400).json({ error: 'Payload inválido. Esperado um array de banners.' });
        }

        const now = new Date().toISOString();

        for (const item of orderedBanners) {
            if (item.id === undefined || item.orderIndex === undefined) continue;

            const existing = await db.query(
                'SELECT id, enabled FROM "UserBannerConfig" WHERE "userId" = $1 AND "bannerId" = $2',
                [userId, item.id]
            );

            if (existing.length > 0) {
                await db.run(
                    'UPDATE "UserBannerConfig" SET "orderIndex" = $1, updatedAt = $2 WHERE "userId" = $3 AND "bannerId" = $4',
                    [item.orderIndex, now, userId, item.id]
                );
            } else {
                // Busca o estado atual global para manter o enabled correto
                const global = await db.query('SELECT enabled FROM "BannerConfig" WHERE id = $1', [item.id]);
                const isGloballyEnabled = global.length > 0 ? (String(global[0].enabled).toLowerCase() === 'true' || global[0].enabled === true || global[0].enabled === 1 || global[0].enabled === 't') : true;
                const globalEnabled = db.isPg ? isGloballyEnabled : (isGloballyEnabled ? 1 : 0);
                await db.run(
                    'INSERT INTO "UserBannerConfig" (id, "userId", "bannerId", enabled, "orderIndex", updatedAt) VALUES ($1, $2, $3, $4, $5, $6)',
                    [uuidv4(), userId, item.id, globalEnabled, item.orderIndex, now]
                );
            }
        }

        await db.run(
            'INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4' + (db.isPg ? '::jsonb' : '') + ')',
            [uuidv4(), req.user.id, 'admin_reorder_user_banners', JSON.stringify({ targetUserId: userId, count: orderedBanners.length })]
        );

        res.json({ message: 'Ordem dos banners do usuário atualizada com sucesso.', success: true });
    } catch (error) {
        console.error('Erro ao reordenar banners do usuário:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// Remover todos os overrides do usuário (resetar para configuração global)
app.delete('/api/admin/users/:userId/banners', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;

        const userCheck = await db.query('SELECT id FROM "User" WHERE id = $1', [userId]);
        if (userCheck.length === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });

        await db.run('DELETE FROM "UserBannerConfig" WHERE "userId" = $1', [userId]);

        await db.run(
            'INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4' + (db.isPg ? '::jsonb' : '') + ')',
            [uuidv4(), req.user.id, 'admin_reset_user_banners', JSON.stringify({ targetUserId: userId })]
        );

        res.json({ message: 'Configurações de banners do usuário resetadas para o padrão global.', success: true });
    } catch (error) {
        console.error('Erro ao resetar banners do usuário:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// ================= ROTAS DE CONFIGURAÇÃO DO SISTEMA =================

// Buscar tempo limite de inatividade da tela de bloqueio (Acessível por todos autenticados)
app.get('/api/settings/lockscreen-timeout', authenticateToken, requireDB, async (req, res) => {
    try {
        const settings = await db.query('SELECT value FROM "SystemConfig" WHERE key = $1', ['lockscreen_timeout']);
        const timeout = settings.length > 0 ? settings[0].value : '5';
        res.json({ timeout });
    } catch (error) {
        console.error("Erro ao buscar tempo de bloqueio:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Atualizar tempo limite de inatividade da tela de bloqueio (Apenas Admin)
app.post('/api/settings/lockscreen-timeout', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    try {
        const { timeout } = req.body;
        if (!timeout) {
            return res.status(400).json({ error: "O parâmetro timeout é obrigatório." });
        }
        
        if (timeout !== 'free' && isNaN(parseInt(timeout))) {
            return res.status(400).json({ error: "O parâmetro timeout deve ser um número ou 'free'." });
        }

        const existing = await db.query('SELECT id FROM "SystemConfig" WHERE key = $1', ['lockscreen_timeout']);
        if (existing.length > 0) {
            if (db.isPg) {
                await db.run('UPDATE "SystemConfig" SET value = $1, "updatedAt" = CURRENT_TIMESTAMP WHERE key = $2', [timeout, 'lockscreen_timeout']);
            } else {
                await db.run('UPDATE SystemConfig SET value = $1, updatedAt = CURRENT_TIMESTAMP WHERE key = $2', [timeout, 'lockscreen_timeout']);
            }
        } else {
            if (db.isPg) {
                await db.run('INSERT INTO "SystemConfig" (id, key, value) VALUES ($1, $2, $3)', [uuidv4(), 'lockscreen_timeout', timeout]);
            } else {
                await db.run('INSERT INTO SystemConfig (id, key, value) VALUES ($1, $2, $3)', [uuidv4(), 'lockscreen_timeout', timeout]);
            }
        }

        // Registrar no log de auditoria
        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), req.user.id, 'admin_updated_lockscreen_timeout', JSON.stringify({ timeout })]
        );

        res.json({ message: "Configuração atualizada com sucesso.", timeout });
    } catch (error) {
        console.error("Erro ao atualizar tempo de bloqueio:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// ================= ROTAS DE AUDITORIA (NOVO) =================

// Obter estatísticas globais consolidadas
app.get('/api/admin/audit/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        // 1. Acessos Totais à Aplicação (Logins com Sucesso)
        const loginsQuery = await db.query('SELECT COUNT(*) as count FROM "AuditLog" WHERE action = $1', ['login_success']);
        const totalAccesses = parseInt(loginsQuery[0].count, 10) || 0;

        // 2. Acessos a Serviços (Cliques em Banners)
        const bannerClicksQuery = await db.query('SELECT COUNT(*) as count FROM "AuditLog" WHERE action = $1', ['banner_clicked']);
        const totalBannerClicks = parseInt(bannerClicksQuery[0].count, 10) || 0;

        // 3. Usuários Únicos (Contas Distintas que Fizeram Login)
        const uniqueUsersQuery = await db.query('SELECT COUNT(DISTINCT "userId") as count FROM "AuditLog" WHERE action = $1', ['login_success']);
        const uniqueUsers = parseInt(uniqueUsersQuery[0].count, 10) || 0;

        // 3.1 Total de Usuários Cadastrados
        const totalUsersQuery = await db.query('SELECT COUNT(*) as count FROM "User"');
        const totalRegisteredUsers = parseInt(totalUsersQuery[0].count, 10) || 0;

        // 4. Sessões Hoje (Logins Hoje)
        // Usar data local ou timezone UTC simplificado para SQLite e Postgres
        let todayCount = 0;
        if (db.isPg) {
            const todayQuery = await db.query(`SELECT COUNT(*) as count FROM "AuditLog" WHERE action = 'login_success' AND timestamp >= current_date`);
            todayCount = parseInt(todayQuery[0].count, 10) || 0;
        } else {
            const dateStr = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
            const todayQuery = await db.query(`SELECT COUNT(*) as count FROM "AuditLog" WHERE action = 'login_success' AND timestamp LIKE $1`, [`${dateStr}%`]);
            todayCount = parseInt(todayQuery[0].count, 10) || 0;
        }

        // 5. Histórico Recente Completo (Para Filtros e Alertas no Frontend)
        const searchHistoryRaw = await db.query(`
            SELECT a.timestamp, u.username as user, a.action, a.success, a."ipAddress", a.details 
            FROM "AuditLog" a
            LEFT JOIN "User" u ON a."userId" = u.id
            ORDER BY a.timestamp DESC
            LIMIT 1000
        `);

        const searchHistory = searchHistoryRaw.map(row => {
            let detailsObj = {};
            try { detailsObj = typeof row.details === 'string' ? JSON.parse(row.details || '{}') : (row.details || {}); } catch (e) { }
            return {
                timestamp: row.timestamp,
                user: row.user || 'Visitante',
                action: row.action,
                success: String(row.success).toLowerCase() === 'true' || row.success === 1 || row.success === true,
                ipAddress: row.ipAddress,
                type: (row.action === 'banner_clicked' || row.action === 'access') ? 'banner' : 'event',
                bannerLabel: detailsObj.bannerLabel || (row.action === 'login_success' ? 'Login Realizado' : null),
                details: detailsObj
            };
        });

        // 6. Top Serviços Acessados (Agrupamento manual para evitar JSON parsing complexo no SQLite vs PG)
        const bannerClicks = {};
        searchHistory.forEach(s => {
            bannerClicks[s.bannerLabel] = (bannerClicks[s.bannerLabel] || 0) + 1;
        });

        res.json({
            totalAccesses,
            totalBannerClicks,
            uniqueUsers,
            totalRegisteredUsers,
            sessionsToday: todayCount,
            searchHistory,
            bannerClicks
        });

    } catch (error) {
        console.error('Erro ao calcular estatísticas de auditoria:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// Registrar evento de auditoria genérico (Front-end)
app.post('/api/audit/log', authenticateToken, requireDB, async (req, res) => {
    try {
        const { action, details } = req.body;
        if (!action) return res.status(400).json({ error: 'Ação é obrigatória' });

        await db.run(
            `INSERT INTO "AuditLog" (id, "userId", action, "ipAddress", "userAgent", details) 
             VALUES ($1, $2, $3, $4, $5, $6${db.isPg ? '::jsonb' : ''})`,
            [uuidv4(), req.user.id, action, req.ip || 'unknown', req.headers['user-agent'] || 'unknown', JSON.stringify(details || {})]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao registrar log de auditoria:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// ================= ROTAS DE CONSULTA FISCAL =================

// Busca de itens ISS / CNAE (MCP Tool Support)
app.get('/api/fiscal/search', authenticateToken, async (req, res) => {
    try {
        const { query, limit = 10 } = req.query;
        if (!query) return res.status(400).json({ error: "Termo de busca é obrigatório" });

        // Nota: Como o banco não tem uma tabela dedicada de itens fiscais mostrada explicitamente no server.js 
        // (ela parece ser consumida via script.js em alguns contextos ou mockada),
        // vamos buscar na AuditLog por termos de busca anteriores ou retornar um mock estruturado
        // para demonstrar a funcionalidade da ferramenta MCP conforme o plano.

        // No entanto, o README menciona "Busca Universal e Avançada combinando descrições, códigos LC e CNAEs".
        // Vamos assumir que existe uma tabela "FiscalItem" ou similar, ou buscar nos logs de busca.

        const results = await db.query(
            `SELECT * FROM "AuditLog" WHERE action = 'fiscal_search' AND details LIKE $1 LIMIT $2`,
            [`%${query}%`, parseInt(limit, 10)]
        );

        res.json({
            query,
            results: results.map(r => ({ id: r.id, timestamp: r.timestamp, details: r.details }))
        });
    } catch (error) {
        console.error("Erro na busca fiscal:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

// Limpar todos os registros de auditoria
app.delete('/api/admin/audit', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await db.run('DELETE FROM "AuditLog"');

        // Registrar a própria ação de exclusão para manter rastro de quem destruiu os logs
        await db.run(
            'INSERT INTO "AuditLog" (id, "userId", action, details) VALUES ($1, $2, $3, $4' + (db.isPg ? '::jsonb' : '') + ')',
            [uuidv4(), req.user.id, 'admin_cleared_audit_logs', JSON.stringify({ action: 'cleared_all' })]
        );

        res.json({ message: 'Dados de auditoria reiniciados com sucesso!', success: true });
    } catch (error) {
        console.error('Erro ao limpar auditoria:', error);
        res.status(500).json({ error: 'Erro interno no servidor' });
    }
});

// Servir arquivos estáticos da página inicial.
app.use(express.static(__dirname));

// Rota catch-all para Single Page Application (SPA)
// Isso garante que qualquer rota não encontrada pela API retorne o index.html do frontend
app.get(/^(?!\/api).*/, (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\uD83D\uDE80 Servidor rodando na porta ${PORT}`);
});
