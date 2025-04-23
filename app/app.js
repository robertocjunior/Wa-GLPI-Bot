const { create, decryptMedia } = require('@open-wa/wa-automate');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const moment = require('moment');
const mime = require('mime-types');
const FormData = require('form-data');
const WebSocket = require('ws');

// ==============================================
// CONFIGURAÇÃO INICIAL
// ==============================================

const pastaDestino = './anexos';
const configFile = './glpi_config.json';
let config = null;
let whatsappClient = null;

// Cria a pasta de destino se não existir
if (!fs.existsSync(pastaDestino)) {
    fs.mkdirSync(pastaDestino);
}

// Tratamento de erros não capturados
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});

// Função para carregar ou criar configuração
function loadOrCreateConfig() {
    if (fs.existsSync(configFile)) {
        try {
            return JSON.parse(fs.readFileSync(configFile, 'utf8'));
        } catch (e) {
            console.error('❌ Erro ao carregar configuração:', e);
            process.exit(1);
        }
    } else {
        // Cria configuração inicial apenas com usuário padrão
        const salt = bcrypt.genSaltSync(10);
        const defaultConfig = {
            glpi: {}, // Configurações do GLPI vazias
            auth: {
                username: 'admin',
                passwordHash: bcrypt.hashSync('admin', salt),
                requireLogin: true
            }
        };

        fs.writeFileSync(configFile, JSON.stringify(defaultConfig, null, 2));
        console.log('✅ Arquivo de configuração criado com usuário padrão');
        console.log('Usuário: admin | Senha: admin');
        return defaultConfig;
    }
}

// Carrega a configuração
config = loadOrCreateConfig();

// Carrega configuração existente
if (fs.existsSync(configFile)) {
    try {
        const savedConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        config = { ...config, ...savedConfig };
        console.log('✅ Configuração carregada:', config);
    } catch (e) {
        console.error('❌ Erro ao carregar configuração:', e);
    }
}

// ==============================================
// SERVIDOR WEB PARA CONFIGURAÇÃO
// ==============================================

const app = express();

// Configuração de sessão
app.use(session({
    secret: 'sua_chave_secreta_muito_segura_' + Math.random().toString(36).substring(2),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Defina como true se estiver usando HTTPS
        maxAge: 24 * 60 * 60 * 1000, // 24 horas
        httpOnly: true // Adicionado para segurança
    }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// ==============================================
// WEBSOCKET PARA COMUNICAÇÃO EM TEMPO REAL
// ==============================================

const wss = new WebSocket.Server({ noServer: true });

// Função para enviar logs para todos os clientes WebSocket
function broadcastLog(message, type = 'info') {
    const logEntry = {
        type: 'log',
        data: {
            type: type,
            message: message,
            timestamp: new Date().toISOString()
        }
    };
    
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(logEntry));
        }
    });
}

// Redireciona console.log para o WebSocket
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;
const originalConsoleInfo = console.info;

console.log = (...args) => {
    originalConsoleLog.apply(console, args);
    broadcastLog(args.join(' '), 'info');
};

console.error = (...args) => {
    originalConsoleError.apply(console, args);
    broadcastLog(args.join(' '), 'error');
};

console.warn = (...args) => {
    originalConsoleWarn.apply(console, args);
    broadcastLog(args.join(' '), 'warn');
};

console.info = (...args) => {
    originalConsoleInfo.apply(console, args);
    broadcastLog(args.join(' '), 'info');
};

// Função para enviar status para todos os clientes WebSocket
function broadcastStatus() {
    const status = {
        type: 'status',
        connected: whatsappClient ? whatsappClient.isConnected() : false
    };

    wss.clients.forEach(wsClient => {
        if (wsClient.readyState === WebSocket.OPEN) {
            wsClient.send(JSON.stringify(status));
        }
    });
}

// ==============================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ==============================================

function requireLogin(req, res, next) {
    // Rotas públicas que não requerem autenticação
    const publicRoutes = ['/login', '/logout', '/auth'];

    // Se não requer login ou se está autenticado ou é rota pública, continua
    if (!config.auth.requireLogin || req.session.loggedin || publicRoutes.includes(req.path)) {
        return next();
    }

    // Se a requisição é para a API, retorna erro JSON
    if (req.originalUrl.startsWith('/api')) {
        return res.status(401).json({ success: false, message: 'Não autenticado' });
    }

    // Caso contrário, redireciona para login
    return res.redirect('/login');
}

// ==============================================
// ROTAS DE AUTENTICAÇÃO
// ==============================================

app.get('/login', (req, res) => {
    // Remove a verificação de loggedin para evitar loop
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (username === config.auth.username && await bcrypt.compare(password, config.auth.passwordHash)) {
        req.session.loggedin = true;
        req.session.username = username;
        return res.json({ success: true, redirect: '/' });
    } else {
        return res.status(401).json({ success: false, message: 'Credenciais inválidas' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Rota raiz protegida
app.get('/', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==============================================
// ROTAS DO WHATSAPP
// ==============================================

app.get('/api/whatsapp/status', requireLogin, (req, res) => {
    if (whatsappClient && whatsappClient.isConnected()) {
        return res.json({ connected: true });
    } else {
        return res.json({ connected: false });
    }
});

app.post('/api/whatsapp/refresh', requireLogin, (req, res) => {
    if (whatsappClient) {
        whatsappClient.logout()
            .then(() => {
                return whatsappClient.initialize();
            })
            .then(() => {
                return res.json({ success: true });
            })
            .catch(err => {
                console.error('Erro ao recarregar WhatsApp:', err);
                return res.status(500).json({ success: false, error: err.message });
            });
    } else {
        return res.status(400).json({ success: false, error: 'Client WhatsApp não inicializado' });
    }
});

// ==============================================
// ROTAS DE CONFIGURAÇÃO
// ==============================================

app.get('/config', requireLogin, (req, res) => {
    res.json(config);
});

app.post('/config', requireLogin, async (req, res) => {
    const { glpiUrl, appToken, userToken, adminUsername, adminPassword, currentPassword } = req.body;

    // Verifica se está tentando alterar credenciais
    if ((adminUsername || adminPassword) && !await bcrypt.compare(currentPassword, config.auth.passwordHash)) {
        return res.status(401).json({ success: false, error: 'Senha atual incorreta' });
    }

    // Atualiza credenciais se fornecidas
    if (adminUsername) config.auth.username = adminUsername;
    if (adminPassword) {
        const salt = await bcrypt.genSalt(10);
        config.auth.passwordHash = await bcrypt.hash(adminPassword, salt);
    }

    // Atualiza configurações do GLPI apenas se todos os campos forem fornecidos
    if (glpiUrl && appToken && userToken) {
        config.glpi = {
            url: glpiUrl.endsWith('/') ? glpiUrl.slice(0, -1) : glpiUrl,
            appToken,
            userToken
        };
    }

    // Salva no arquivo
    fs.writeFileSync(configFile, JSON.stringify(config, null, 2));

    res.json({
        success: true,
        message: 'Configuração atualizada com sucesso!',
        glpiConfigured: !!config.glpi?.url
    });

    // Se o GLPI foi configurado agora, tenta iniciar o bot
    if (glpiUrl && appToken && userToken) {
        console.log('🔄 GLPI configurado - Tentando iniciar o bot...');
        setTimeout(() => {
            iniciarBot(1); // Reinicia com tentativa 1
        }, 2000);
    }
});

app.get('/api/config/status', requireLogin, (req, res) => {
    res.json({
        glpiConfigured: !!config.glpi?.url && !!config.glpi?.appToken && !!config.glpi?.userToken,
        missingFields: {
            url: !config.glpi?.url,
            appToken: !config.glpi?.appToken,
            userToken: !config.glpi?.userToken
        },
        authConfigured: true
    });
});

// ==============================================
// FUNÇÕES DO GLPI
// ==============================================

async function iniciarSessaoGLPI() {
    if (!config.glpi || !config.glpi.url || !config.glpi.appToken || !config.glpi.userToken) {
        throw new Error('Configuração do GLPI não encontrada');
    }
    try {
        const response = await axios.get(`${config.glpi.url}/initSession`, {
            headers: {
                "App-Token": config.glpi.appToken,
                "Authorization": `user_token ${config.glpi.userToken}`
            }
        });

        const session_token = response.data.session_token;
        console.log("✅ Sessão GLPI iniciada! Token:", session_token);
        return session_token;
    } catch (error) {
        console.error("❌ Erro ao iniciar sessão:", error.response ? error.response.data : error.message);
        return null;
    }
}

async function consultarChamadoGLPI(ticket_id) {
    let session_token = null;
    try {
        session_token = await iniciarSessaoGLPI();

        if (!session_token) {
            throw new Error("Falha ao obter o token de sessão.");
        }

        // Consulta o ticket
        const ticketUrl = `${config.glpi.url}/search/Ticket?` +
            `criteria[0][field]=2&criteria[0][searchtype]=contains&criteria[0][value]=${ticket_id}` +
            `&forcedisplay[0]=2&forcedisplay[1]=1&forcedisplay[2]=15&forcedisplay[3]=12&forcedisplay[4]=5`;

        const ticketResponse = await axios.get(ticketUrl, {
            headers: {
                "App-Token": config.glpi.appToken,
                "Session-Token": session_token,
                "Accept": "application/json"
            }
        });

        if (!ticketResponse.data || ticketResponse.data.totalcount === 0 || !ticketResponse.data.data.length) {
            console.log("❌ Nenhum chamado encontrado.");
            return null;
        }

        const chamado = ticketResponse.data.data[0];
        let tecnicoResponsavel = null;

        if (chamado["5"]) {
            const tecnicoUrl = `${config.glpi.url}/search/User?` +
                `criteria[0][field]=2&criteria[0][searchtype]=contains&criteria[0][value]=${chamado["5"]}` +
                `&forcedisplay[0]=9`;

            const tecnicoResponse = await axios.get(tecnicoUrl, {
                headers: {
                    "App-Token": config.glpi.appToken,
                    "Session-Token": session_token,
                    "Accept": "application/json"
                }
            });

            if (tecnicoResponse.data && tecnicoResponse.data.data && tecnicoResponse.data.data.length > 0) {
                tecnicoResponsavel = tecnicoResponse.data.data[0]["9"];
            }
        }

        return {
            id: chamado["2"] ?? "ID não encontrado",
            titulo: chamado["1"] ?? "Sem título",
            criado_em: chamado["15"] ? moment(chamado["15"]).format("DD/MM/YYYY HH:mm") : "Data não disponível",
            status: mapearStatus(chamado["12"]),
            tecnico: tecnicoResponsavel
        };
    } catch (error) {
        console.error("❌ Erro ao consultar o chamado:", error.response ? error.response.data : error.message);
        return null;
    } finally {
        if (session_token) {
            await encerrarSessaoGLPI(session_token);
        }
    }
}

async function criarChamado(nome, descricaoBreve, descricaoDetalhada, anexos = []) {
    let session_token = null;
    try {
        session_token = await iniciarSessaoGLPI();

        if (!session_token) {
            throw new Error("Falha ao obter o token de sessão.");
        }

        let userId = null;
        const userUrl = `${config.glpi.url}/search/User?` +
            `criteria[0][field]=9&criteria[0][searchtype]=contains&criteria[0][value]=${encodeURIComponent(nome)}` +
            `&forcedisplay[0]=1&forcedisplay[1]=9&forcedisplay[2]=2`;

        const userResponse = await axios.get(userUrl, {
            headers: {
                "App-Token": config.glpi.appToken,
                "Session-Token": session_token,
                "Accept": "application/json"
            }
        });

        if (userResponse.data && userResponse.data.totalcount === 1 && userResponse.data.data.length === 1) {
            userId = userResponse.data.data[0]["2"];
            console.log(`✅ Usuário encontrado no GLPI: ID ${userId}`);
        } else if (userResponse.data && userResponse.data.totalcount > 1) {
            console.log(`⚠️ Múltiplos usuários encontrados para "${nome}". Não associando a nenhum.`);
        }

        let conteudoChamado = `${descricaoDetalhada}<br><br>Enviado por: ${nome}<br>`;

        for (const anexo of anexos) {
            if (mime.lookup(anexo).startsWith('image/')) {
                const fileContent = fs.readFileSync(anexo, { encoding: 'base64' });
                const imageTag = `<br><img src="data:${mime.lookup(anexo)};base64,${fileContent}" alt="Anexo" style="max-width: 600px; height: auto;" /><br>`;
                conteudoChamado += `\n\n${imageTag}`;
            }
        }

        const url = `${config.glpi.url}/Ticket`;
        const body = {
            input: {
                name: descricaoBreve,
                content: conteudoChamado
            }
        };

        if (userId) {
            body.input["_users_id_requester"] = userId;
        }

        const response = await axios.post(url, body, {
            headers: {
                "Session-Token": session_token,
                "App-Token": config.glpi.appToken,
                "Content-Type": "application/json"
            }
        });

        console.log("✅ Chamado criado com sucesso:", response.data);

        if (anexos.length > 0) {
            for (const anexo of anexos) {
                await anexarArquivoAoChamado(response.data.id, anexo, session_token);
            }

            for (const anexo of anexos) {
                try {
                    fs.unlinkSync(anexo);
                    console.log(`🗑️ Arquivo removido: ${anexo}`);
                } catch (err) {
                    console.error(`❌ Erro ao remover arquivo ${anexo}:`, err);
                }
            }
        }

        return response.data;
    } catch (error) {
        console.error("❌ Erro ao criar chamado:", error.response ? error.response.data : error.message);
        return null;
    } finally {
        if (session_token) {
            await encerrarSessaoGLPI(session_token);
        }
    }
}

async function anexarArquivoAoChamado(ticketId, filePath, session_token) {
    try {
        const url = `${config.glpi.url}/Document/`;

        const form = new FormData();
        form.append('uploadManifest', JSON.stringify({
            input: {
                name: path.basename(filePath),
                _filename: [path.basename(filePath)]
            }
        }));
        form.append('uploadFile', fs.createReadStream(filePath), {
            filename: path.basename(filePath),
            contentType: mime.lookup(filePath) || 'application/octet-stream'
        });

        console.log("📤 Enviando arquivo para o GLPI...");

        const documentResponse = await axios.post(url, form, {
            headers: {
                "Session-Token": session_token,
                "App-Token": config.glpi.appToken,
                ...form.getHeaders()
            }
        });

        const documentId = documentResponse.data.id;
        console.log("✅ Documento enviado com sucesso. ID:", documentId);

        const associationUrl = `${config.glpi.url}/Document_Item/`;
        const associationData = {
            input: {
                documents_id: documentId,
                items_id: ticketId,
                itemtype: "Ticket"
            }
        };

        const associationResponse = await axios.post(associationUrl, associationData, {
            headers: {
                "Session-Token": session_token,
                "App-Token": config.glpi.appToken,
                "Content-Type": "application/json"
            }
        });

        console.log("✅ Anexo associado ao chamado com sucesso:", associationResponse.data);
    } catch (error) {
        console.error("❌ Erro ao anexar arquivo ao chamado:", error.response ? error.response.data : error.message);
        throw error;
    }
}

async function encerrarSessaoGLPI(session_token) {
    if (!session_token) {
        console.log("⚠️ Nenhum token de sessão fornecido para encerramento");
        return false;
    }

    try {
        const response = await axios.get(`${config.glpi.url}/killSession`, {
            headers: {
                "App-Token": config.glpi.appToken,
                "Session-Token": session_token
            }
        });

        console.log("🔍 Resposta da API ao encerrar sessão:", JSON.stringify(response.data, null, 2));

        if (response.data === true) {
            console.log(`✅ Sessão GLPI encerrada com sucesso (Token: ${session_token})`);
            return true;
        } else if (response.data && response.data.session_token === session_token) {
            console.log(`✅ Sessão GLPI encerrada com sucesso (Token: ${session_token})`);
            return true;
        }

        console.log("⚠️ Resposta inesperada ao encerrar sessão:", response.data);
        return false;
    } catch (error) {
        console.error("❌ Erro ao encerrar sessão GLPI:", {
            message: error.message,
            response: error.response ? error.response.data : null,
            stack: error.stack
        });
        return false;
    }
}

// ==============================================
// FUNÇÕES AUXILIARES
// ==============================================

function gerarStringAleatoria(tamanho) {
    const caracteres = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let resultado = '';
    for (let i = 0; i < tamanho; i++) {
        resultado += caracteres.charAt(Math.floor(Math.random() * caracteres.length));
    }
    return resultado;
}

function gerarNomeUnico(extensao) {
    const timestamp = moment().format('YYYYMMDDHHmmss');
    const randomString = gerarStringAleatoria(6);
    return `${timestamp}_${randomString}.${extensao}`;
}

function mapearStatus(statusCode) {
    const statusMap = {
        1: "Aguardando Atendimento",
        2: "Em Atendimento",
        3: "Em Atendimento",
        4: "Aguardando Atendimento",
        5: "Resolvido",
        6: "Resolvido"
    };
    return statusMap[statusCode] || "Desconhecido";
}

// ==============================================
// BOT WHATSAPP
// ==============================================

async function iniciarBot(tentativa = 1) {
    // Verificação inicial da configuração do GLPI
    if (!config.glpi || !config.glpi.url || !config.glpi.appToken || !config.glpi.userToken) {
        console.error('❌ Bot não iniciado - Configuração do GLPI incompleta');
        console.error('Por favor, configure o GLPI através da interface web');

        // Verifica novamente após um tempo
        const intervalo = Math.min(10000 * tentativa, 60000);
        console.log(`🔄 Tentando novamente em ${intervalo / 1000} segundos... (Tentativa ${tentativa})`);

        setTimeout(() => {
            // Recarrega a configuração antes de tentar novamente
            try {
                const savedConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
                config = { ...config, ...savedConfig };
                console.log('🔄 Configuração recarregada');
            } catch (e) {
                console.error('❌ Erro ao recarregar configuração:', e);
            }

            iniciarBot(tentativa + 1);
        }, intervalo);
        return;
    }

    console.log('✅ Configuração do GLPI encontrada. Iniciando bot...');

    const timeoutSessoes = {};
    const TEMPO_INATIVIDADE = 60 * 60 * 1000;
    let usuariosAtendidos = {};
    let estadoUsuario = {};

    async function encerrarConversaInativa(client, sender) {
        try {
            await client.sendText(sender, "⏳ Sua sessão foi encerrada automaticamente devido à inatividade. Se precisar de ajuda, inicie uma nova conversa.");

            delete usuariosAtendidos[sender];
            delete estadoUsuario[sender];
            delete timeoutSessoes[sender];

            console.log(`♻️ Sessão encerrada por inatividade: ${sender}`);
        } catch (error) {
            console.error("❌ Erro ao encerrar conversa inativa:", error);
        }
    }

    function reiniciarTimerInatividade(client, sender) {
        if (!client) {
            console.error('Cliente WhatsApp não está disponível');
            return;
        }

        if (timeoutSessoes[sender]) {
            clearTimeout(timeoutSessoes[sender]);
        }

        timeoutSessoes[sender] = setTimeout(async () => {
            await encerrarConversaInativa(client, sender);
        }, TEMPO_INATIVIDADE);
    }

    try {
        whatsappClient = await create({
            sessionId: 'my-session',
            headless: true,
            qrTimeout: 0,
            authTimeout: 0,
            useChrome: false,
            skipUpdateCheck: true,
            logConsole: false,
            //executablePath: '/usr/bin/chromium-browser',
            executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', // Caminho padrão do Chrome no Windows
            qrLogSkip: false,
            qrFormat: 'base64',
            multiDevice: false,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--disable-gpu'
            ],
            launchTimeout: 60000,
            waitForRipeSession: true
        });

        // Verificação se o cliente foi criado corretamente
        if (!whatsappClient) {
            throw new Error('Falha ao criar instância do WhatsApp');
        }

        console.log('Tipo do whatsappClient:', typeof whatsappClient);
        console.log('Cliente pronto?', whatsappClient ? 'Sim' : 'Não');

        // Evento para capturar o QR Code
        whatsappClient.onStateChanged(async (state) => {
            console.log('Estado do WhatsApp alterado:', state);

            if (state === 'qr') {
                const qrCode = await whatsappClient.getQRCode();
                console.log('QR Code recebido');

                // Envia o QR Code para todos os clientes WebSocket
                wss.clients.forEach(wsClient => {
                    if (wsClient.readyState === WebSocket.OPEN) {
                        wsClient.send(JSON.stringify({
                            type: 'qr',
                            data: qrCode
                        }));
                    }
                });
            }

            // Atualiza o status de conexão
            broadcastStatus();
        });

        console.log('🤖 Bot iniciado com sucesso!');

        whatsappClient.onMessage(async message => {
            const sender = message.from;

            reiniciarTimerInatividade(whatsappClient, sender);

            console.log("📩 Mensagem recebida de:", sender, "Conteúdo:", message.body);
            console.log("📌 Estado atual:", estadoUsuario[sender]);

            if (message.body === "#") {
                if (timeoutSessoes[sender]) {
                    clearTimeout(timeoutSessoes[sender]);
                    delete timeoutSessoes[sender];
                }

                await whatsappClient.simulateTyping(sender, true)
                await new Promise(resolve => setTimeout(resolve, 2000));
                await whatsappClient.simulateTyping(sender, false)

                await whatsappClient.sendText(sender, "🔚 Atendimento encerrado.");
                delete usuariosAtendidos[sender];
                delete estadoUsuario[sender];
                return;
            }

            if (!usuariosAtendidos[sender]) {
                usuariosAtendidos[sender] = true;
                estadoUsuario[sender] = {};

                await whatsappClient.simulateTyping(sender, true)
                await new Promise(resolve => setTimeout(resolve, 2000));
                await whatsappClient.simulateTyping(sender, false)

                await whatsappClient.sendText(sender,
                    "Olá, como posso te ajudar?\n\n" +
                    "1️⃣ - Abrir chamado\n" +
                    "2️⃣ - Acompanhar chamado\n" +
                    "0️⃣ - Sair"
                );
                await whatsappClient.sendText(sender, "Para sair, a qualquer momento digite *#*.");
                return;
            }

            if (!estadoUsuario[sender] || estadoUsuario[sender].estado === "aguardando_comando") {
                estadoUsuario[sender] = {};

                await whatsappClient.simulateTyping(sender, true)
                await new Promise(resolve => setTimeout(resolve, 2000));
                await whatsappClient.simulateTyping(sender, false)

                await whatsappClient.sendText(sender, "Olá, como posso te ajudar?\n\n" +
                    "1️⃣ - Abrir chamado\n" +
                    "2️⃣ - Acompanhar chamado\n" +
                    "0️⃣ - Sair"
                );
                return;
            }

            if (!estadoUsuario[sender]) {
                estadoUsuario[sender] = {};
            }

            if (message.body === "1") {
                estadoUsuario[sender].estado = "abrir_chamado";

                await whatsappClient.simulateTyping(sender, true)
                await new Promise(resolve => setTimeout(resolve, 2000));
                await whatsappClient.simulateTyping(sender, false)

                await whatsappClient.sendText(sender, "Ótimo, descreva em poucas palavras qual o seu problema.");
            } else if (estadoUsuario[sender].estado === "abrir_chamado") {
                let descricaoBreve = message.body.trim();
                estadoUsuario[sender].descricaoBreve = descricaoBreve;
                await whatsappClient.sendText(sender, "Agora, descreva de forma detalhada o seu problema.");
                estadoUsuario[sender].estado = "aguardar_descricao_detalhada";
            } else if (estadoUsuario[sender].estado === "aguardar_descricao_detalhada") {
                estadoUsuario[sender].descricaoDetalhada = message.body.trim();

                if (estadoUsuario[sender].descricaoDetalhada) {
                    await whatsappClient.sendText(sender, "Agora, você pode enviar anexos (fotos, documentos, etc.). Quando terminar, digite 0 para continuar.");
                    estadoUsuario[sender].estado = "aguardar_anexos";
                } else {
                    await whatsappClient.sendText(sender, "⚠️ Por favor, insira uma descrição detalhada.");
                }
            } else if (estadoUsuario[sender].estado === "aguardar_anexos") {
                if (message.body === "0") {
                    await whatsappClient.sendText(sender, "Agora, com quem estou falando?");
                    await hatsappClient.sendText(sender, "Diga apenas seu primeiro nome, sem cargo ou setor");
                    estadoUsuario[sender].estado = "aguardar_nome";
                } else if (message.mimetype) {
                    try {
                        const mediaData = await decryptMedia(message);
                        const fileExtension = mime.extension(message.mimetype) || 'bin';
                        const fileName = gerarNomeUnico(fileExtension);
                        const filePath = path.join(pastaDestino, fileName);

                        fs.writeFileSync(filePath, mediaData);
                        console.log(`Anexo salvo em: ${filePath}`);

                        if (!estadoUsuario[sender].anexos) {
                            estadoUsuario[sender].anexos = [];
                        }
                        estadoUsuario[sender].anexos.push(filePath);

                        await whatsappClient.sendText(sender, `✅ ${estadoUsuario[sender].anexos.length} anexo(s) recebido(s) e salvos. Envie outro anexo ou digite 0 para continuar.`);
                    } catch (error) {
                        console.error("❌ Erro ao processar anexo:", error);
                        await whatsappClient.sendText(sender, "❌ Erro ao processar anexo. Tente novamente.");
                    }
                } else {
                    await whatsappClient.sendText(sender, "❌ Mensagem inválida. Envie um anexo ou digite 0 para continuar.");
                }
            } else if (estadoUsuario[sender].estado === "aguardar_nome") {
                estadoUsuario[sender].nomeUsuario = message.body.trim();

                let respostaChamado = await criarChamado(
                    estadoUsuario[sender].nomeUsuario,
                    estadoUsuario[sender].descricaoBreve,
                    estadoUsuario[sender].descricaoDetalhada,
                    estadoUsuario[sender].anexos || []
                );

                if (estadoUsuario[sender].anexos) {
                    delete estadoUsuario[sender].anexos;
                }

                if (respostaChamado) {
                    await whatsappClient.simulateTyping(sender, true)
                    await new Promise(resolve => setTimeout(resolve, 2000));
                    await whatsappClient.simulateTyping(sender, false)

                    await whatsappClient.sendText(sender, `✅ Seu chamado foi criado com sucesso! Número do chamado: ${respostaChamado.id}\n\n` +
                        "Para sair, digite #.");
                } else {
                    await whatsappClient.simulateTyping(sender, true)
                    await new Promise(resolve => setTimeout(resolve, 2000));
                    await whatsappClient.simulateTyping(sender, false)

                    await whatsappClient.sendText(sender, "❌ Não foi possível criar o chamado. Tente novamente mais tarde." + `\n\n Para sair, digite #.`);
                }

                estadoUsuario[sender].estado = "aguardando_comando";
            } else if (message.body === "2") {
                estadoUsuario[sender].estado = "acompanhar_chamado";

                await whatsappClient.simulateTyping(sender, true)
                await new Promise(resolve => setTimeout(resolve, 2000));
                await whatsappClient.simulateTyping(sender, false)

                await whatsappClient.sendText(sender, "🔍 Informe o número do seu chamado.");
            } else if (estadoUsuario[sender].estado === "acompanhar_chamado") {
                let ticketId = message.body.trim();
                let ticketData = await consultarChamadoGLPI(ticketId);

                if (ticketData) {
                    let mensagem = `📄 *Detalhes do Chamado #${ticketData.id}:*\n\n` +
                        `🔹 *Título:* ${ticketData.titulo}\n` +
                        `📅 *Criado em:* ${ticketData.criado_em}\n` +
                        `📌 *Status:* ${ticketData.status}`;

                    if (ticketData.tecnico) {
                        mensagem += `\n👤 *Técnico Responsável:* ${ticketData.tecnico}`;
                    }

                    mensagem += `\n\nPara sair, digite #.`;

                    await whatsappClient.simulateTyping(sender, true)
                    await new Promise(resolve => setTimeout(resolve, 2000));
                    await whatsappClient.simulateTyping(sender, false)

                    await whatsappClient.sendText(sender, mensagem);
                } else {
                    await whatsappClient.sendText(sender, "❌ Não foi possível encontrar o chamado. Verifique o número e tente novamente.");
                }

                estadoUsuario[sender].estado = "aguardando_comando";
            } else if (message.body === "0") {
                await whatsappClient.sendText(sender, "👋 Obrigado pelo contato!");
                delete usuariosAtendidos[sender];
                delete estadoUsuario[sender];
            } else {
                await whatsappClient.simulateTyping(sender, true)
                await new Promise(resolve => setTimeout(resolve, 2000));
                await whatsappClient.simulateTyping(sender, false)

                await whatsappClient.sendText(sender, "❌ Opção inválida! Escolha uma opção válida:\n\n" +
                    "1️⃣ - Abrir chamado\n" +
                    "2️⃣ - Acompanhar chamado\n" +
                    "0️⃣ - Sair"
                );
            }
        });

        // Notifica que a conexão foi estabelecida
        broadcastStatus();

    } catch (error) {
        console.error("❌ Erro no bot:", error);
        console.log("🔄 Reiniciando o bot...");
        setTimeout(() => {
            iniciarBot(tentativa + 1);
        }, 5000);
    }
}

// ==============================================
// INICIALIZAÇÃO DO SERVIDOR
// ==============================================

const PORT = process.env.PORT || 3000;

function startServer(port) {
    const server = app.listen(port, () => {
        console.log(`🌐 Servidor web rodando na porta ${port}`);
        console.log(`Acesse a interface em: http://localhost:${port}/login`);

        // Integra o WebSocket com o servidor HTTP
        server.on('upgrade', (request, socket, head) => {
            wss.handleUpgrade(request, socket, head, ws => {
                wss.emit('connection', ws, request);
            });
        });

        // Inicia o bot após um pequeno delay
        setTimeout(() => {
            iniciarBot(1);
        }, 50000);
    });

    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.log(`⚠️ Porta ${port} em uso, tentando porta ${port + 1}...`);
            startServer(port + 1);
        } else {
            console.error('❌ Erro no servidor:', err);
        }
    });
}

// Inicia o servidor
startServer(PORT);