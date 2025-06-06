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
const he = require('he'); // Adiciona a biblioteca he
const { fileTypeFromBuffer } = require('file-type');

// ==============================================
// CONFIGURAÇÃO INICIAL
// ==============================================

const pastaDestino = './anexos';
const SESSION_DATA_PATH = './whatsapp_session_data'; // Pasta para guardar os dados da sessão do WhatsApp
const configFile = './glpi_config.json';
let config = null;
let whatsappClient = null;

// Cria a pasta de destino se não existir
if (!fs.existsSync(pastaDestino)) {
    fs.mkdirSync(pastaDestino);
}

// Cria a pasta de dados da sessão do WhatsApp se não existir
if (!fs.existsSync(SESSION_DATA_PATH)) {
    fs.mkdirSync(SESSION_DATA_PATH);
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

// Carrega configuração existente (redundant with the above but kept for safety if logic changes)
if (fs.existsSync(configFile)) {
    try {
        const savedConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        config = { ...config, ...savedConfig }; // Merge, savedConfig takes precedence
    } catch (e) {
        console.error('❌ Erro ao carregar configuração existente:', e);
    }
}

// ==============================================
// SERVIDOR WEB PARA CONFIGURAÇÃO
// ==============================================

const app = express();

app.use(session({
    secret: 'sua_chave_secreta_muito_segura_' + Math.random().toString(36).substring(2),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, 
        maxAge: 24 * 60 * 60 * 1000, 
        httpOnly: true 
    }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// ==============================================
// WEBSOCKET PARA COMUNICAÇÃO EM TEMPO REAL
// ==============================================

const wss = new WebSocket.Server({ noServer: true });

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

function broadcastStatus() {
    const status = {
        type: 'status',
        connected: !!(whatsappClient && typeof whatsappClient.isConnected === 'function' && whatsappClient.isConnected())
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
    const publicRoutes = ['/login', '/logout', '/auth'];
    if (!config.auth.requireLogin || req.session.loggedin || publicRoutes.includes(req.path)) {
        return next();
    }
    if (req.originalUrl.startsWith('/api')) {
        return res.status(401).json({ success: false, message: 'Não autenticado' });
    }
    return res.redirect('/login');
}

// ==============================================
// ROTAS DE AUTENTICAÇÃO E DASHBOARD
// ==============================================

app.get('/login', (req, res) => {
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

app.get('/', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==============================================
// ROTAS DO WHATSAPP (API para Dashboard)
// ==============================================

app.get('/api/whatsapp/status', requireLogin, (req, res) => {
    if (whatsappClient && typeof whatsappClient.isConnected === 'function' && whatsappClient.isConnected()) {
        return res.json({ connected: true });
    } else {
        return res.json({ connected: false });
    }
});

app.post('/api/whatsapp/refresh', requireLogin, (req, res) => {
    if (whatsappClient && typeof whatsappClient.isConnected === 'function' && whatsappClient.isConnected()) {
        whatsappClient.logout()
            .then(() => {
                console.log('Logout realizado, tentando reinicializar...');
                return create({
                    sessionId: 'my-session', headless: true, qrTimeout: 0, authTimeout: 0, 
                    sessionDataPath: SESSION_DATA_PATH, skipUpdateCheck: true, logConsole: false, 
                    //executablePath: process.env.CHROME_BIN || '/usr/bin/chromium-browser',
                    executablePath: process.env.CHROME_BIN || 'C:/Program Files/Google/Chrome/Application/chrome.exe',
                    qrLogSkip: false, qrFormat: 'base64', multiDevice: true, 
                    args: ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage','--disable-accelerated-2d-canvas','--no-first-run','--no-zygote','--disable-gpu'],
                    launchTimeout: 120000, waitForRipeSession: true, killProcessOnBrowserClose: true,
                });
            })
            .then(newClient => {
                whatsappClient = newClient; 
                setupWhatsappListeners(); 
                console.log('Cliente WhatsApp recarregado e ouvintes reconfigurados.');
                broadcastStatus();
                return res.json({ success: true, message: "Cliente WhatsApp recarregado." });
            })
            .catch(err => {
                console.error('Erro ao recarregar WhatsApp:', err);
                return res.status(500).json({ success: false, error: err.message });
            });
    } else if (whatsappClient) { 
         console.log('Cliente WhatsApp existe mas não está conectado. Tentando reinicializar...');
         iniciarBot(1, true); 
         return res.json({ success: true, message: "Tentativa de reinicialização do cliente WhatsApp iniciada." });
    }
    else {
        console.log('Cliente WhatsApp não inicializado. Tentando iniciar...');
        iniciarBot(1, true); 
        return res.status(400).json({ success: false, error: 'Client WhatsApp não inicializado, tentativa de início em progresso.' });
    }
});

// ==============================================
// ROTAS DE CONFIGURAÇÃO (API para Dashboard)
// ==============================================

app.get('/config', requireLogin, (req, res) => {
    res.json(config);
});

app.post('/config', requireLogin, async (req, res) => {
    const { glpiUrl, appToken, userToken, adminUsername, adminPassword, currentPassword, requireLogin: authRequireLogin } = req.body;

    if ((adminUsername || adminPassword) && !currentPassword) {
        return res.status(400).json({ success: false, error: 'Senha atual é obrigatória para alterar credenciais.' });
    }
    if ((adminUsername || adminPassword) && currentPassword && !await bcrypt.compare(currentPassword, config.auth.passwordHash)) {
        return res.status(401).json({ success: false, error: 'Senha atual incorreta' });
    }

    if (adminUsername) config.auth.username = adminUsername;
    if (adminPassword) {
        const salt = await bcrypt.genSalt(10);
        config.auth.passwordHash = await bcrypt.hash(adminPassword, salt);
    }

    if (typeof authRequireLogin !== 'undefined') {
        config.auth.requireLogin = authRequireLogin === 'true' || authRequireLogin === true;
    }

    if (glpiUrl !== undefined || appToken !== undefined || userToken !== undefined) {
        config.glpi = {
            url: glpiUrl ? (glpiUrl.endsWith('/') ? glpiUrl.slice(0, -1) : glpiUrl) : (config.glpi?.url || ''),
            appToken: appToken || (config.glpi?.appToken || ''),
            userToken: userToken || (config.glpi?.userToken || '')
        };
    }

    fs.writeFileSync(configFile, JSON.stringify(config, null, 2));

    res.json({
        success: true,
        message: 'Configuração atualizada com sucesso!',
        glpiConfigured: !!(config.glpi?.url && config.glpi?.appToken && config.glpi?.userToken),
        authRequireLogin: config.auth.requireLogin
    });

    if (config.glpi?.url && config.glpi?.appToken && config.glpi?.userToken) {
        console.log('🔄 Configuração do GLPI salva - Tentando iniciar/reiniciar o bot...');
        setTimeout(() => {
            if (whatsappClient) {
                console.log('Reiniciando o bot existente...');
                whatsappClient.kill().then(() => { 
                    whatsappClient = null; 
                    iniciarBot(1, true); 
                }).catch(err => {
                    console.error('Erro ao matar cliente antigo, prosseguindo com nova instância:', err);
                    whatsappClient = null;
                    iniciarBot(1, true); 
                });
            } else {
                iniciarBot(1, true); 
            }
        }, 2000);
    } else {
        console.log('Configuração do GLPI incompleta. Bot não será iniciado/reiniciado.')
    }
});

app.get('/api/config/status', requireLogin, (req, res) => {
    res.json({
        glpiConfigured: !!(config.glpi?.url && config.glpi?.appToken && config.glpi?.userToken),
        missingFields: {
            url: !config.glpi?.url,
            appToken: !config.glpi?.appToken,
            userToken: !config.glpi?.userToken
        },
        authConfigured: true, 
        requireLogin: config.auth.requireLogin
    });
});

// ==============================================
// FUNÇÕES DO GLPI
// ==============================================

async function iniciarSessaoGLPI() {
    if (!config.glpi || !config.glpi.url || !config.glpi.appToken || !config.glpi.userToken) {
        throw new Error('Configuração do GLPI não encontrada ou incompleta');
    }
    try {
        const response = await axios.get(`${config.glpi.url}/initSession`, {
            headers: {
                "App-Token": config.glpi.appToken,
                "Authorization": `user_token ${config.glpi.userToken}`
            }
        });
        return response.data.session_token;
    } catch (error) {
        console.error("❌ Erro ao iniciar sessão GLPI:", error.response ? error.response.data : error.message);
        return null;
    }
}

async function consultarChamadoGLPI(ticket_id) {
    let session_token = null;
    try {
        session_token = await iniciarSessaoGLPI();
        if (!session_token) throw new Error("Falha ao obter o token de sessão para consulta.");

        const ticketUrl = `${config.glpi.url}/search/Ticket?` +
            `criteria[0][field]=2&criteria[0][searchtype]=contains&criteria[0][value]=${ticket_id}` +
            `&forcedisplay[0]=2&forcedisplay[1]=1&forcedisplay[2]=15&forcedisplay[3]=12&forcedisplay[4]=5&forcedisplay[5]=24&forcedisplay[6]=25`;

        const ticketResponse = await axios.get(ticketUrl, {
            headers: { "App-Token": config.glpi.appToken, "Session-Token": session_token, "Accept": "application/json" }
        });

        if (!ticketResponse.data || ticketResponse.data.totalcount === 0 || !ticketResponse.data.data.length) {
            console.log(`❌ Nenhum chamado encontrado com ID: ${ticket_id}.`);
            return null;
        }

        const chamado = ticketResponse.data.data[0];
        let tecnicoResponsavel = null;

        if (chamado["5"]) { 
            const tecnicoUrl = `${config.glpi.url}/search/User?criteria[0][field]=2&criteria[0][searchtype]=equals&criteria[0][value]=${chamado["5"]}&forcedisplay[0]=9`;
            const tecnicoResponse = await axios.get(tecnicoUrl, {
                headers: { "App-Token": config.glpi.appToken, "Session-Token": session_token, "Accept": "application/json" }
            });
            if (tecnicoResponse.data && tecnicoResponse.data.data && tecnicoResponse.data.data.length > 0) {
                tecnicoResponsavel = tecnicoResponse.data.data[0]["9"]; 
            }
        }

        let acompanhamentos = null;
        if (chamado["25"]) {
            if (Array.isArray(chamado["25"])) {
                acompanhamentos = chamado["25"];
            } else {
                acompanhamentos = [chamado["25"]]; // Trata como array mesmo se for string única
            }
        }

        return {
            id: chamado["2"] ?? "ID não encontrado", titulo: chamado["1"] ?? "Sem título",
            criado_em: chamado["15"] ? moment(chamado["15"]).format("DD/MM/YYYY HH:mm") : "Data não disponível",
            status: mapearStatus(chamado["12"]), tecnico: tecnicoResponsavel || "Não atribuído",
            solucao: chamado["24"] || null, 
            acompanhamento: acompanhamentos 
        };
    } catch (error) {
        console.error(`❌ Erro ao consultar o chamado ${ticket_id}:`, error.response ? error.response.data : error.message);
        return null;
    } finally {
        if (session_token) await encerrarSessaoGLPI(session_token);
    }
}

async function criarChamado(nomeRequisitante, descricaoBreve, descricaoDetalhada, numeroTelefone, anexosPaths = [], specificUserId = null, selectedGlpiUserName = null) {
    let session_token = null;
    const arquivosParaAnexarSeparadamente = [...anexosPaths]; // Clona para não modificar o original se necessário, e já é a lista que queremos
    let glpiUserNameForLink = null; // Para armazenar o nome do usuário GLPI se encontrado nesta chamada

    try {
        session_token = await iniciarSessaoGLPI();
        if (!session_token) throw new Error("Falha ao obter o token de sessão para criar chamado.");

        let userIdToAssociate = specificUserId;


        if (!specificUserId && nomeRequisitante) {
            const userUrl = `${config.glpi.url}/search/User?` +
                `criteria[0][field]=9&criteria[0][searchtype]=contains&criteria[0][value]=${encodeURIComponent(nomeRequisitante)}` + 
                `&forcedisplay[0]=1&forcedisplay[1]=9&forcedisplay[2]=2&forcedisplay[3]=34`; 

            const userResponse = await axios.get(userUrl, {
                headers: { "App-Token": config.glpi.appToken, "Session-Token": session_token, "Accept": "application/json" }
            });

            if (userResponse.data && userResponse.data.totalcount === 1 && userResponse.data.data.length === 1) {
                userIdToAssociate = userResponse.data.data[0]["2"]; 
                const glpiUser = userResponse.data.data[0];
                glpiUserNameForLink = glpiUser["9"]; // firstName
                if (glpiUser["34"] && glpiUser["34"] !== glpiUser["9"]) { // lastNameOrFullName
                    glpiUserNameForLink += ` ${glpiUser["34"]}`;
                }
                console.log(`✅ Usuário único encontrado no GLPI: ID ${userIdToAssociate} para "${nomeRequisitante}", nome GLPI: "${glpiUserNameForLink}"`);
            } else if (userResponse.data && userResponse.data.totalcount > 1) {
                console.log(`⚠️ Múltiplos usuários (${userResponse.data.totalcount}) encontrados para "${nomeRequisitante}". Retornando lista para seleção.`);
                return {
                    multipleUsersFound: true,
                    users: userResponse.data.data.map(u => ({
                        id: u["2"], username: u["1"], firstName: u["9"], lastNameOrFullName: u["34"] || '' 
                    })),
                    originalNomeRequisitante: nomeRequisitante, descricaoBreve, descricaoDetalhada, anexos: anexosPaths,
                    // selectedGlpiUserName não é relevante aqui, pois a seleção ainda não ocorreu
                };
            } else {
                console.log(`ℹ️ Nenhum usuário encontrado no GLPI para "${nomeRequisitante}". O chamado será criado sem associação de requisitante.`);
                userIdToAssociate = null; 
            }
        } else if (specificUserId) {
             console.log(`ℹ️ Usando ID de usuário GLPI fornecido diretamente: ${specificUserId}`);
        }

        let conteudoChamadoHTML = `<p>${descricaoDetalhada.replace(/\n/g, '<br>')}</p>`; 

        // Construir a informação do solicitante ANTES de adicionar as imagens
        let infoSolicitanteHTML = '';
        if (numeroTelefone) {
            const telefoneLimpo = numeroTelefone.replace(/@c\.us$/, ''); // Remove @c.us do final
            
            // Determina o nome a ser usado no TEXTO do link do WhatsApp
            let nomeParaUsarNoLinkInternoWhatsapp;
            if (selectedGlpiUserName) { // Prioridade 1: Nome do GLPI passado após seleção do usuário
                nomeParaUsarNoLinkInternoWhatsapp = selectedGlpiUserName;
            } else if (glpiUserNameForLink) { // Prioridade 2: Nome do GLPI encontrado na busca desta função
                nomeParaUsarNoLinkInternoWhatsapp = glpiUserNameForLink;
            } else { // Fallback: Nome fornecido pelo requisitante no chat
                nomeParaUsarNoLinkInternoWhatsapp = nomeRequisitante;
            }

            const tituloChamadoParaLink = descricaoBreve;
            const textoWhatsapp = `Olá *${encodeURIComponent(nomeParaUsarNoLinkInternoWhatsapp)}*, vi que você abriu um chamado na nossa central com o assunto *${encodeURIComponent(tituloChamadoParaLink)}*, poderia me dar mais algumas informações sobre`;
            const linkWhatsapp = `https://api.whatsapp.com/send/?phone=${telefoneLimpo}&text=${textoWhatsapp}&type=phone_number&app_absent=0`;
            
            infoSolicitanteHTML = `<p><br>Chamado aberto por ${nomeRequisitante} pelo WhatsApp através do número <a href="${linkWhatsapp}" target="_blank" rel="noopener noreferrer">${telefoneLimpo}</a>.</p>`;
        } else {
            infoSolicitanteHTML = `<p><br>Chamado aberto por ${nomeRequisitante} (via WhatsApp).</p>`; // Fallback caso não haja número
        }
        conteudoChamadoHTML += infoSolicitanteHTML;

        for (const anexoPath of anexosPaths) {
            const mimeType = mime.lookup(anexoPath);
            
            if (mimeType && mimeType.startsWith('image/')) {
                try {
                    const fileContentBase64 = await fs.promises.readFile(anexoPath, { encoding: 'base64' });
                    const imageTag = `<p><img src="data:${mimeType};base64,${fileContentBase64}" alt="Anexo de Imagem ${path.basename(anexoPath)}" style="max-width: 600px; height: auto; border: 1px solid #ddd; padding: 5px; margin-top:10px;" /></p>`;
                    conteudoChamadoHTML += imageTag;
                    console.log(`🖼️ Imagem ${path.basename(anexoPath)} incorporada no chamado.`);
                } catch (imgError) {
                    console.error(`❌ Erro ao ler ou incorporar imagem ${anexoPath}:`, imgError);
                    // A imagem já está em arquivosParaAnexarSeparadamente (pois anexosPaths foi clonado no início),
                    // então será tratada como anexo normal mesmo se a incorporação falhar.
                }
            }
        }
        // A antiga seção 'infoRemetente' foi substituída e integrada acima.

        const ticketPayload = {
            input: {
                name: descricaoBreve, 
                content: conteudoChamadoHTML, 
                "itilcategories_id": 0, 
                "type": 2, 
                "urgency": 3, 
            }
        };

        if (userIdToAssociate) {
            ticketPayload.input["_users_id_requester"] = userIdToAssociate;
        }

        const createTicketUrl = `${config.glpi.url}/Ticket`;
        const response = await axios.post(createTicketUrl, ticketPayload, {
            headers: { "Session-Token": session_token, "App-Token": config.glpi.appToken, "Content-Type": "application/json" }
        });

        console.log("✅ Chamado criado com sucesso no GLPI:", response.data);
        const ticketId = response.data.id;

        if (arquivosParaAnexarSeparadamente.length > 0) {
            console.log(`📎 Iniciando upload de ${arquivosParaAnexarSeparadamente.length} anexo(s) para o chamado ID ${ticketId}...`);
            for (const anexoPath of arquivosParaAnexarSeparadamente) {
                if (fs.existsSync(anexoPath)) { 
                    await anexarArquivoAoChamado(ticketId, anexoPath, session_token);
                } else {
                    console.warn(`⚠️ Arquivo ${anexoPath} não encontrado para anexo separado. Pulando.`);
                }
            }
        }
        return response.data; 

    } catch (error) {
        console.error("❌ Erro detalhado ao criar chamado no GLPI:",
            error.response ? { data: error.response.data, status: error.response.status } : error.message,
            error.stack
        );
        return null;
    } finally { // A limpeza dos arquivos agora é feita pela limpeza da pasta de sessão em handleMessageLogic
        if (session_token) {
            await encerrarSessaoGLPI(session_token);
        }
    }
}

async function anexarArquivoAoChamado(ticketId, filePath, session_token_param) {
    let session_token = session_token_param;
    let manageSessionInternally = false;

    try {
        if (!session_token) {
            session_token = await iniciarSessaoGLPI();
            if (!session_token) throw new Error("Falha ao obter token de sessão para anexar arquivo.");
            manageSessionInternally = true;
        }

        const url = `${config.glpi.url}/Document/`;
        const form = new FormData();
        const fileName = path.basename(filePath);

        form.append('uploadManifest', JSON.stringify({
            input: { name: fileName, _filename: [fileName] }
        }));
        form.append('filename[0]', fs.createReadStream(filePath), { 
            filename: fileName, contentType: mime.lookup(filePath) || 'application/octet-stream'
        });

        console.log(`📤 Enviando arquivo "${fileName}" para o GLPI como anexo separado...`);
        const documentResponse = await axios.post(url, form, {
            headers: { "Session-Token": session_token, "App-Token": config.glpi.appToken, ...form.getHeaders() }
        });

        const documentId = documentResponse.data.id;
        console.log(`✅ Documento (anexo separado) enviado com sucesso. ID do Documento: ${documentId}`);

        const associationUrl = `${config.glpi.url}/Document_Item/`;
        const associationData = {
            input: { documents_id: documentId, items_id: ticketId, itemtype: "Ticket" }
        };
        const associationResponse = await axios.post(associationUrl, associationData, {
            headers: { "Session-Token": session_token, "App-Token": config.glpi.appToken, "Content-Type": "application/json" }
        });
        console.log(`✅ Anexo separado (Documento ID ${documentId}) associado ao chamado ID ${ticketId} com sucesso.`);
    } catch (error) {
        console.error(`❌ Erro ao anexar arquivo "${path.basename(filePath)}" separadamente ao chamado ${ticketId}:`,
            error.response ? { data: error.response.data, status: error.response.status } : error.message
        );
    } finally {
        if (manageSessionInternally && session_token) {
            await encerrarSessaoGLPI(session_token);
        }
    }
}

async function encerrarSessaoGLPI(session_token) {
    if (!session_token || !config.glpi || !config.glpi.url) return false;
    try {
        await axios.get(`${config.glpi.url}/killSession`, {
            headers: { "App-Token": config.glpi.appToken, "Session-Token": session_token }
        });
        return true;
    } catch (error) {
        if (error.response && error.response.status !== 401) {
            console.error(`❌ Erro ao encerrar sessão GLPI:`, error.response ? error.response.data : error.message);
        } else if (!error.response) {
             console.error(`❌ Erro de rede ao encerrar sessão GLPI:`, error.message);
        }
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
    const timestamp = moment().format('YYYYMMDDHHmmssSSS'); 
    const randomString = gerarStringAleatoria(6);
    return `${timestamp}_${randomString}.${extensao}`;
}

function mapearStatus(statusCode) {
    const statusMap = {
        1: "Aguardando atendimento", // Novo
        2: "Em atendimento", // Em Atendimento (Atribuído)
        3: "Em atendimento", // Em Atendimento (Planejado)
        4: "Em atendimento", // Pendente (considerado em atendimento para simplificar)
        5: "Resolvido",       // Solucionado
        6: "Resolvido"        // Fechado
    };
    const statusNumber = parseInt(statusCode, 10);
    if (statusMap[statusNumber]) {
        return statusMap[statusNumber];
    }
    return `Desconhecido (${statusCode})`;
}

function gerarNomePastaSessaoAnexos() {
    return `${moment().format('YYYYMMDDHHmmssSSS')}_${gerarStringAleatoria(8)}`;
}

async function limparPastaSessaoAnexos(sessionPath) {
    if (sessionPath && fs.existsSync(sessionPath)) {
        console.log(`🗑️ Limpando pasta de sessão de anexos: ${sessionPath}`);
        try {
            await fs.promises.rm(sessionPath, { recursive: true, force: true });
            console.log(`✅ Pasta de sessão de anexos ${sessionPath} limpa com sucesso.`);
        } catch (err) {
            console.error(`❌ Erro ao limpar pasta de sessão de anexos ${sessionPath}:`, err);
        }
    } else if (sessionPath) {
        console.log(`ℹ️ Pasta de sessão de anexos ${sessionPath} não encontrada para limpeza (pode já ter sido limpa ou nunca criada).`);
    }
}
// ==============================================
// BOT WHATSAPP
// ==============================================
let userMessageProcessing = {}; // Alterado de flag global para objeto por usuário

async function processMessageSafe(client, message) {
    const sender = message.from;

    if (userMessageProcessing[sender]) {
        // Se a mensagem atual é uma mídia E o usuário está no estado de anexos,
        // permite que ela seja processada. Isso é para lidar com álbuns onde
        // múltiplas mensagens de mídia chegam rapidamente.
        if (estadoUsuario[sender]?.estado === "abrir_chamado_anexos" && message.mimetype) {
            console.log(`ℹ️  Processamento de anexo para ${sender} (álbum/múltiplos). Permitindo passagem...`);
        } else {
            console.warn(`⚠️  Processamento de mensagem anterior ainda em curso para ${sender}. Nova mensagem (tipo: ${message.type}, body: "${message.body ? message.body.substring(0,30) : ''}") ignorada por enquanto.`);
            return; // Ignora a nova mensagem se uma já estiver em processamento e não for um anexo esperado
        }
    }

    userMessageProcessing[sender] = true;
    try {
        await handleMessageLogic(client, message); 
    } catch (error) {
        console.error("❌ Erro crítico no processamento da mensagem para", sender, ":", error);
        const sessionPathToClean = estadoUsuario[sender]?.dadosTemporarios?.attachmentSessionPath;
        try {
            await sendAndLogText(client, sender, "❌ Ocorreu um erro inesperado. Por favor, tente novamente mais tarde ou digite # para recomeçar.");
        } catch (sendError) {
            console.error("❌ Falha ao enviar mensagem de erro para o usuário:", sendError);
        }
        delete usuariosAtendidos[sender];
        await limparPastaSessaoAnexos(sessionPathToClean); // Limpa a pasta antes de deletar os dados temporários
        delete estadoUsuario[sender];
        if (timeoutSessoes[sender]) {
            clearTimeout(timeoutSessoes[sender]);
            delete timeoutSessoes[sender];
        }
    } finally {
        userMessageProcessing[sender] = false;
    }
}

const timeoutSessoes = {};
const TEMPO_INATIVIDADE = 15 * 60 * 1000; 
let usuariosAtendidos = {};
let estadoUsuario = {};

async function encerrarConversaInativa(client, sender) {
    try {
        if (usuariosAtendidos[sender] || estadoUsuario[sender]) { 
            const sessionPathToClean = estadoUsuario[sender]?.dadosTemporarios?.attachmentSessionPath;
            await sendAndLogText(client, sender, "⏳ Sua sessão foi encerrada automaticamente devido à inatividade. Se precisar de ajuda, envie qualquer mensagem para iniciar uma nova conversa.");
            delete usuariosAtendidos[sender];
            await limparPastaSessaoAnexos(sessionPathToClean);
            delete estadoUsuario[sender];
            if (timeoutSessoes[sender]) {
                 clearTimeout(timeoutSessoes[sender]);
                 delete timeoutSessoes[sender];
            }
            console.log(`♻️ Sessão encerrada por inatividade para: ${sender}`);
        }
    } catch (error) {
        console.error(`❌ Erro ao encerrar conversa inativa para ${sender}:`, error);
    }
}

function reiniciarTimerInatividade(client, sender) {
    if (!client || typeof client.sendText !== 'function') { 
        console.error('Cliente WhatsApp inválido ou não disponível para reiniciar timer.');
        return;
    }
    if (timeoutSessoes[sender]) {
        clearTimeout(timeoutSessoes[sender]);
    }
    timeoutSessoes[sender] = setTimeout(async () => {
        await encerrarConversaInativa(client, sender);
    }, TEMPO_INATIVIDADE);
}

async function iniciarBot(tentativa = 1, forceRestart = false) {
    if (whatsappClient && !forceRestart) {
        if (typeof whatsappClient.isConnected === 'function' && whatsappClient.isConnected()) {
            console.log("✅ Bot já conectado.");
            broadcastStatus();
            return;
        }
        console.log("⏳ Bot existente não conectado, aguardando finalização da tentativa atual ou reinício forçado.");
        return; 
    }

    if (whatsappClient && forceRestart) {
        console.log("🔄 Forçando reinício do bot...");
        try {
            await whatsappClient.kill(); 
            console.log("Cliente antigo fechado.");
        } catch (e) {
            console.error("Erro ao fechar cliente antigo, pode já estar fechado:", e.message);
        }
        whatsappClient = null; 
    }

    if (!config.glpi || !config.glpi.url || !config.glpi.appToken || !config.glpi.userToken) {
        console.error(`❌ Bot não iniciado (Tentativa ${tentativa}) - Configuração do GLPI incompleta.`);
        broadcastLog('Configuração do GLPI incompleta. Verifique a interface web.', 'error');
        const intervalo = 15000; 
        console.log(`🔄 Tentando recarregar configuração e reiniciar bot em ${intervalo / 1000} segundos...`);
        setTimeout(() => {
            try {
                const savedConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
                config = { ...config, ...savedConfig };
            } catch (e) {
                console.error('❌ Erro ao recarregar configuração antes de nova tentativa do bot:', e);
            }
            iniciarBot(tentativa + 1, false); 
        }, intervalo);
        return;
    }

    console.log(`✅ Configuração do GLPI encontrada. Iniciando bot... (Tentativa ${tentativa})`);
    broadcastLog('Iniciando conexão com o WhatsApp...', 'info');

    try {
        whatsappClient = await create({
            sessionId: 'my-session', headless: true, qrTimeout: 0, authTimeout: 0,
            sessionDataPath: SESSION_DATA_PATH, skipUpdateCheck: true, logConsole: false, 
            //executablePath: process.env.CHROME_BIN || '/usr/bin/chromium-browser',
            executablePath: process.env.CHROME_BIN || 'C:/Program Files/Google/Chrome/Application/chrome.exe',
            qrLogSkip: false, qrFormat: 'base64', multiDevice: true, 
            args: ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage','--disable-accelerated-2d-canvas','--no-first-run','--no-zygote','--disable-gpu'],
            launchTimeout: 120000, waitForRipeSession: true, killProcessOnBrowserClose: true,
        });

        if (!whatsappClient || typeof whatsappClient.isConnected !== 'function') {
            throw new Error('Falha ao criar instância do WhatsApp ou instância inválida.');
        }
        console.log('✅ Cliente WhatsApp criado. Configurando ouvintes...');
        setupWhatsappListeners(); 
    } catch (error) {
        console.error(`❌ Erro crítico ao iniciar bot (Tentativa ${tentativa}):`, error.message);
        whatsappClient = null; 
        broadcastLog(`Erro ao iniciar WhatsApp: ${error.message}. Tentando novamente...`, 'error');
        broadcastStatus(); 
        const intervaloErro = 15000; 
        console.log(`🔄 Reiniciando o bot devido a erro em ${intervaloErro / 1000} segundos...`);
        setTimeout(() => {
            iniciarBot(tentativa + 1, false); 
        }, intervaloErro);
    }
}

function setupWhatsappListeners() {
    if (!whatsappClient) {
        console.error("❌ Tentativa de configurar ouvintes sem cliente WhatsApp inicializado.");
        return;
    }
    console.log("🎧 Configurando ouvintes de eventos do WhatsApp...");

    whatsappClient.onStateChanged(async (state) => {
        console.log('🔄 Estado do WhatsApp alterado:', state);
        broadcastLog(`Estado do WhatsApp: ${state}`, 'info');
        if (state === 'qr') {
            try {
                const qrCode = await whatsappClient.getQrCode(); 
                if (qrCode) {
                    console.log('📲 QR Code recebido. Enviando para WebSocket...');
                    wss.clients.forEach(wsClient => {
                        if (wsClient.readyState === WebSocket.OPEN) {
                            wsClient.send(JSON.stringify({ type: 'qr', data: qrCode }));
                        }
                    });
                } else { console.warn("⚠️ QR Code recebido como nulo/vazio."); }
            } catch (qrError) { console.error("❌ Erro ao obter QR Code:", qrError); }
        } else if (state === 'CONNECTED') {
            console.log('✅ WhatsApp Conectado!');
            broadcastLog('WhatsApp conectado com sucesso!', 'success');
        } else if (['TIMEOUT', 'UNLAUNCHED', 'CONFLICT', 'UNPAIRED', 'DISCONNECTED'].includes(state)) {
            console.warn(`⚠️ WhatsApp desconectado ou em estado problemático: ${state}.`);
            broadcastLog(`WhatsApp desconectado: ${state}. Será feita uma tentativa de reconexão.`, 'warn');
            if (whatsappClient && typeof whatsappClient.kill === 'function') {
                whatsappClient.kill().then(() => {
                    whatsappClient = null; 
                    console.log("Cliente anterior finalizado. Agendando reinício do bot...");
                    setTimeout(() => iniciarBot(1, true), 5000); 
                }).catch(err => {
                    console.error("Erro ao tentar matar cliente para reconexão:", err);
                    whatsappClient = null;
                    setTimeout(() => iniciarBot(1, true), 5000);
                });
            } else {
                 whatsappClient = null;
                 setTimeout(() => iniciarBot(1, true), 5000);
            }
        }
        broadcastStatus();
    });

    whatsappClient.onMessage(async message => {
        // Log de todas as mensagens recebidas
        const senderIdentifier = message.sender.pushname || message.sender.id || message.from;
        let logMessage = `💬 Mensagem recebida`;

        if (message.isGroupMsg) {
            const groupName = message.chat.name || message.chat.id;
            logMessage += ` no grupo "${groupName}" de "${senderIdentifier}"`;
        } else {
            logMessage += ` de "${senderIdentifier}"`;
        }

        if (message.body) {
            logMessage += `: "${message.body.trim()}"`;
        } else if (message.caption) {
            logMessage += ` (legenda): "${message.caption.trim()}"`;
        } else if (message.mimetype) {
            logMessage += ` [Mídia: ${message.mimetype}]`;
        } else if (message.type && message.type !== 'chat') { // 'chat' é o tipo padrão para texto, já coberto por 'body'
            logMessage += ` [Tipo: ${message.type}]`;
        } else {
            logMessage += ` [Conteúdo não textual ou tipo desconhecido]`;
        }
        console.log(logMessage);

        await processMessageSafe(whatsappClient, message);
    });
    
    whatsappClient.onIncomingCall(async (call) => {
        console.log("📞 Chamada recebida, rejeitando:", call);
        try {
            // Não há necessidade de logar a rejeição em si como uma "mensagem enviada"
            // mas a mensagem de texto subsequente sim.
            await whatsappClient.rejectCall(call.id); 
            await sendAndLogText(whatsappClient, call.peerJid, "Desculpe, não posso atender chamadas. Por favor, envie uma mensagem de texto.");
        } catch (rejectError) { console.error("❌ Erro ao rejeitar chamada:", rejectError); }
    });
    console.log('🤖 Ouvintes configurados. Bot pronto para receber mensagens assim que conectado.');
}

// Função auxiliar para enviar mensagem e logar
async function sendAndLogText(clientInstance, recipientId, textContent) {
    console.log(`📤 Enviando mensagem para "${recipientId}": "${textContent}"`);
    await clientInstance.sendText(recipientId, textContent);
}

async function handleMessageLogic(client, message) {
    const sender = message.from;
    const body = message.body ? message.body.trim() : ""; 
    const senderName = message.sender && message.sender.pushname ? message.sender.pushname : sender; 

    if (message.isGroupMsg || message.from === 'status@broadcast') return; 
    reiniciarTimerInatividade(client, sender);

    if (body.toLowerCase() === "#" || body.toLowerCase() === "cancelar") {
        const sessionPathToClean = estadoUsuario[sender]?.dadosTemporarios?.attachmentSessionPath;
        if (timeoutSessoes[sender]) clearTimeout(timeoutSessoes[sender]);
        delete timeoutSessoes[sender];
        delete usuariosAtendidos[sender]; 
        delete estadoUsuario[sender];
        await limparPastaSessaoAnexos(sessionPathToClean);
        await sendAndLogText(client, sender, "🔚 Atendimento encerrado. Se precisar de algo mais, basta enviar uma mensagem. 👋");
        console.log(`🛑 Atendimento encerrado manualmente para ${sender}`);
        return;
    }
    
    if (!usuariosAtendidos[sender] || !estadoUsuario[sender] || !estadoUsuario[sender].estado) {
        usuariosAtendidos[sender] = true; 
        estadoUsuario[sender] = { estado: "aguardando_opcao_inicial", dadosTemporarios: {} };
        await client.simulateTyping(sender, true);
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));
        await client.simulateTyping(sender, false);
        await sendAndLogText(client, sender,
            `Olá ${senderName}, sou seu assistente virtual para suporte GLPI. Como posso te ajudar hoje?\n\n` +
            "1️⃣ - Abrir novo chamado\n" +
            "2️⃣ - Acompanhar chamado existente\n" +
            "0️⃣ - Encerrar conversa"
        );
        await sendAndLogText(client, sender, "A qualquer momento, digite *#* ou *cancelar* para encerrar e voltar ao início.");
        reiniciarTimerInatividade(client, sender); 
        return;
    }

    const currentState = estadoUsuario[sender].estado;
    const dados = estadoUsuario[sender].dadosTemporarios;

    if (currentState === "aguardando_opcao_inicial") {
        if (body === "1") {
            estadoUsuario[sender].estado = "abrir_chamado_descricao_breve";
            const attachmentSessionId = gerarNomePastaSessaoAnexos();
            const attachmentSessionPath = path.join(pastaDestino, attachmentSessionId);
            try {
                await fs.promises.mkdir(attachmentSessionPath, { recursive: true });
                estadoUsuario[sender].dadosTemporarios = { anexos: [], attachmentSessionPath: attachmentSessionPath };
                console.log(`📂 Pasta de sessão de anexos criada: ${attachmentSessionPath} para ${sender}`);
            } catch (mkdirError) {
                console.error(`❌ Erro ao criar pasta de sessão de anexos ${attachmentSessionPath}:`, mkdirError);
                await sendAndLogText(client, sender, "❌ Ocorreu um erro interno ao iniciar o processo de chamado. Por favor, tente novamente.");
                estadoUsuario[sender].estado = "aguardando_opcao_inicial"; // Volta ao estado inicial
                return;
            }
            await sendAndLogText(client, sender, "📝 Entendido! Para abrir um novo chamado, por favor, descreva o problema em poucas palavras (será o título do chamado).");
        } else if (body === "2") {
            estadoUsuario[sender].estado = "acompanhar_chamado_id";
            await sendAndLogText(client, sender, "🔍 Para acompanhar um chamado, por favor, informe o número (ID) do seu chamado.");
        } else if (body === "0") {
            await sendAndLogText(client, sender, "👋 Obrigado pelo contato! Até a próxima.");
            delete usuariosAtendidos[sender]; delete estadoUsuario[sender];
            if (timeoutSessoes[sender]) clearTimeout(timeoutSessoes[sender]); delete timeoutSessoes[sender];
        } else {
            await sendAndLogText(client, sender, "❌ Opção inválida. Por favor, escolha uma das opções do menu (1, 2 ou 0).");
        }
        return;
    }

    if (currentState === "abrir_chamado_descricao_breve") {
        if (!body) { 
            await sendAndLogText(client, sender, "⚠️ O título do chamado não pode ser vazio. Por favor, descreva o problema em poucas palavras.");
            return; 
        }
        dados.descricaoBreve = body;
        estadoUsuario[sender].estado = "abrir_chamado_descricao_detalhada";
        await sendAndLogText(client, sender, "📄 Ótimo. Agora, por favor, descreva detalhadamente o problema.");
    }
    else if (currentState === "abrir_chamado_descricao_detalhada") {
        if (!body) { 
            await sendAndLogText(client, sender, "⚠️ A descrição detalhada do chamado não pode ser vazia. Por favor, forneça os detalhes do problema.");
            return; 
        }
        dados.descricaoDetalhada = body;
        estadoUsuario[sender].estado = "abrir_chamado_anexos";
        await sendAndLogText(client, sender, "🖼️ Se desejar, envie agora arquivos ou imagens como anexo. Quando terminar de enviar os anexos (ou se não houver), digite *0* para prosseguir.");
    }
    else if (currentState === "abrir_chamado_anexos") {
        if (message.type === 'album') {
            // É uma mensagem de contêiner de álbum, apenas aguarde as mídias individuais.
            // Não envie "Entrada inválida".
            console.log(`ℹ️ Mensagem do tipo 'album' recebida de ${sender}. Aguardando mídias individuais.`);
            return; // Retorna para não processar mais nada desta mensagem de 'album'
        }

        if (message.mimetype) { 
            try {
                if (!dados.attachmentSessionPath || !fs.existsSync(dados.attachmentSessionPath)) {
                    console.error(`❌ Pasta de sessão de anexos não encontrada para ${sender}: ${dados.attachmentSessionPath}. Não é possível salvar o anexo.`);
                    await sendAndLogText(client, sender, "❌ Ocorreu um erro ao preparar para receber seu anexo. Por favor, digite *0* e tente abrir o chamado novamente.");
                    return;
                }
                const mediaData = await decryptMedia(message);
                const fileExtension = mime.extension(message.mimetype) || 'bin';
                const fileName = gerarNomeUnico(fileExtension);
                const filePath = path.join(dados.attachmentSessionPath, fileName); // Salva na pasta da sessão
                await fs.promises.writeFile(filePath, mediaData);
                console.log(`📎 Anexo salvo localmente: ${filePath} para ${sender}`);
                if (!dados.anexos) dados.anexos = [];
                dados.anexos.push(filePath); 
                await sendAndLogText(client, sender, `✅ ${dados.anexos.length} anexo(s) recebido(s). Envie outro ou digite *0* para continuar.`);
            } catch (error) {
                console.error(`❌ Erro ao processar anexo de ${sender}:`, error);
                await sendAndLogText(client, sender, "❌ Ops! Ocorreu um erro ao processar seu anexo. Tente enviar novamente ou digite *0* para continuar sem este anexo.");
            }
        } else if (body === "0") {
            estadoUsuario[sender].estado = "abrir_chamado_nome_requisitante";
            await sendAndLogText(client, sender, `👤 Para finalizar, por favor, informe seu nome completo para identificação no GLPI.`);
        } else {
            // Se não for 'album' (já tratado), nem mídia com mimetype, nem "0", então é inválido.
            await sendAndLogText(client, sender, "❓ Entrada inválida. Por favor, envie um anexo ou digite *0* para prosseguir.");
        }
    }
    else if (currentState === "abrir_chamado_nome_requisitante") {
        if (!body) { 
            await sendAndLogText(client, sender, "⚠️ O nome do requisitante não pode ser vazio. Por favor, informe seu nome completo.");
            return; 
        }
        dados.nomeRequisitante = body; 
        
        const currentAttachmentSessionPath = dados.attachmentSessionPath; // Guardar para o finally
        let multipleUsersWereFound = false;

        await sendAndLogText(client, sender, "⏳ Processando sua solicitação e buscando seu usuário no GLPI...");
        await client.simulateTyping(sender, true);
        try {
            const resultadoChamado = await criarChamado(
                dados.nomeRequisitante, dados.descricaoBreve, dados.descricaoDetalhada, sender, dados.anexos || [], null, null
            );
            await client.simulateTyping(sender, false);

            if (resultadoChamado && resultadoChamado.multipleUsersFound) {
                multipleUsersWereFound = true; // Sinaliza que a pasta não deve ser limpa ainda
                dados.potentialGlpiUsers = resultadoChamado.users; 
                dados.descricaoBreve = resultadoChamado.descricaoBreve; 
                dados.descricaoDetalhada = resultadoChamado.descricaoDetalhada;
                dados.anexos = resultadoChamado.anexos; // Mantém os anexos
                dados.nomeRequisitante = resultadoChamado.originalNomeRequisitante;
                // dados.attachmentSessionPath é mantido
                estadoUsuario[sender].estado = "abrir_chamado_selecionar_usuario_glpi";
                let userListMessage = "👥 Encontrei mais de um registro com um nome parecido. Por favor, selecione qual deles é você:\n\n";
                resultadoChamado.users.forEach((user, index) => {
                    let displayName = user.firstName;
                    if (user.lastNameOrFullName && user.lastNameOrFullName !== user.firstName) displayName += ` ${user.lastNameOrFullName}`;
                    if (user.username) displayName += ` (${user.username})`;
                    userListMessage += `${index + 1} - ${displayName}\n`;
                });
                userListMessage += "\nDigite o número correspondente ou *#* para cancelar.";
                await sendAndLogText(client, sender, userListMessage);
            } else if (resultadoChamado && resultadoChamado.id) { 
                await sendAndLogText(client, sender, `✅ Chamado criado com sucesso! O número do seu chamado é: *${resultadoChamado.id}*.\n\nObrigado! Se precisar de mais alguma coisa, é só chamar.`);
                delete estadoUsuario[sender].dadosTemporarios; // Limpa dados, incluindo attachmentSessionPath implicitamente
                estadoUsuario[sender].estado = "aguardando_opcao_inicial"; 
                await new Promise(resolve => setTimeout(resolve, 1500));
                await sendAndLogText(client, sender, "Como posso te ajudar agora?\n\n1️⃣ - Abrir novo chamado\n2️⃣ - Acompanhar chamado existente\n0️⃣ - Encerrar conversa");
            } else { 
                await sendAndLogText(client, sender, "❌ Desculpe, ocorreu um erro e não foi possível criar seu chamado. Por favor, tente novamente mais tarde.");
                delete estadoUsuario[sender].dadosTemporarios;
                estadoUsuario[sender].estado = "aguardando_opcao_inicial";
            }
        } catch (errorCriarChamado) {
            console.error(`❌ Erro durante a chamada a criarChamado (nome requisitante) para ${sender}:`, errorCriarChamado);
            await sendAndLogText(client, sender, "❌ Ocorreu um erro interno crítico ao tentar registrar seu chamado. A equipe de suporte foi notificada.");
            delete estadoUsuario[sender].dadosTemporarios;
            estadoUsuario[sender].estado = "aguardando_opcao_inicial";
        } finally {
            if (!multipleUsersWereFound) { // Só limpa a pasta se o fluxo não continuar para seleção de usuário
                await limparPastaSessaoAnexos(currentAttachmentSessionPath);
            }
        }
    }
    else if (currentState === "abrir_chamado_selecionar_usuario_glpi") {
        const selection = parseInt(body, 10);
        if (isNaN(selection) || selection < 1 || selection > dados.potentialGlpiUsers.length) {
            await sendAndLogText(client, sender, `❌ Opção inválida. Por favor, digite um número entre 1 e ${dados.potentialGlpiUsers.length}.`);
            return;
        }

        const currentAttachmentSessionPath = dados.attachmentSessionPath; // Guardar para o finally
        const selectedUser = dados.potentialGlpiUsers[selection - 1];
        await sendAndLogText(client, sender, `⏳ Você selecionou "${selectedUser.firstName}${selectedUser.lastNameOrFullName ? ' '+selectedUser.lastNameOrFullName : ''}". Criando o chamado...`);
        await client.simulateTyping(sender, true);
        
        try {
            let selectedUserNameForLink = selectedUser.firstName;
            if (selectedUser.lastNameOrFullName && selectedUser.lastNameOrFullName !== selectedUser.firstName) selectedUserNameForLink += ` ${selectedUser.lastNameOrFullName}`;
            const resultadoFinalChamado = await criarChamado(
                dados.nomeRequisitante, dados.descricaoBreve, dados.descricaoDetalhada, sender, dados.anexos || [], selectedUser.id, selectedUserNameForLink
            );
            await client.simulateTyping(sender, false);
            if (resultadoFinalChamado && resultadoFinalChamado.id) {
                await sendAndLogText(client, sender, `✅ Chamado criado com sucesso e associado a você! O número do seu chamado é: *${resultadoFinalChamado.id}*.\n\nObrigado!`);
            } else {
                await sendAndLogText(client, sender, "❌ Desculpe, ocorreu um erro ao tentar criar o chamado após a seleção.");
            }
        } catch (errorCriarChamadoFinal) {
            console.error(`❌ Erro durante a chamada a criarChamado (selecionar usuário) para ${sender}:`, errorCriarChamadoFinal);
            await sendAndLogText(client, sender, "❌ Ocorreu um erro interno crítico ao tentar registrar seu chamado após a seleção. A equipe de suporte foi notificada.");
        } finally {
            await limparPastaSessaoAnexos(currentAttachmentSessionPath); // Limpa a pasta da sessão
            delete estadoUsuario[sender].dadosTemporarios; 
            estadoUsuario[sender].estado = "aguardando_opcao_inicial";
            await new Promise(resolve => setTimeout(resolve, 1500));
            await sendAndLogText(client, sender, "Como posso te ajudar agora?\n\n1️⃣ - Abrir novo chamado\n2️⃣ - Acompanhar chamado existente\n0️⃣ - Encerrar conversa");
        }
    }
    else if (currentState === "acompanhar_chamado_id") {
        if (!body || !/^\d+$/.test(body)) { 
            await sendAndLogText(client, sender, "⚠️ Por favor, informe um número de chamado válido.");
            return;
        }
        const ticketId = body;
        await sendAndLogText(client, sender, `⏳ Consultando informações do chamado *#${ticketId}*...`);
        await client.simulateTyping(sender, true);
        const ticketData = await consultarChamadoGLPI(ticketId);
        await client.simulateTyping(sender, false);
        if (ticketData) {
            let mensagem = `📄 *Detalhes do Chamado #${ticketData.id}:*\n\n` +
                `🔹 *Título:* ${ticketData.titulo}\n` + `📅 *Criado em:* ${ticketData.criado_em}\n` +
                `📌 *Status:* ${ticketData.status}\n`;
            if (ticketData.tecnico && ticketData.tecnico !== "Não atribuído") {
                mensagem += `👤 *Técnico Responsável:* ${ticketData.tecnico}`;
            }
            await sendAndLogText(client, sender, mensagem); // Envia os detalhes básicos primeiro

            if (ticketData.solucao) {
                const htmlContentSolucao = he.decode(ticketData.solucao);
                const imgRegexSolucao = /<img[^>]+src="([^"]+)"[^>]*>/i;
                const imgMatchSolucao = htmlContentSolucao.match(imgRegexSolucao);

                if (imgMatchSolucao && imgMatchSolucao[1]) {
                    const imageUrlRelativeSolucao = imgMatchSolucao[1];
                    // Verifica se a URL já é absoluta (http/https) ou se precisa ser construída
                    const absoluteImageUrlSolucao = imageUrlRelativeSolucao.startsWith('http') ? imageUrlRelativeSolucao : new URL(imageUrlRelativeSolucao, config.glpi.url).href;

                    const textContentForCaptionSolucao = htmlContentSolucao.replace(imgRegexSolucao, '').replace(/<[^>]*>/g, '').trim();
                    let captionSolucao = `📝 *Solução:* ${textContentForCaptionSolucao}`;
                    if (captionSolucao.length > 1024) captionSolucao = captionSolucao.substring(0, 1021) + "...";

                    let imageSessionTokenSolucao = null;
                    try {
                        console.log(`📝 Baixando imagem da solução: ${absoluteImageUrlSolucao}`);
                        // Só inicia sessão GLPI se for URL interna
                        if (absoluteImageUrlSolucao.startsWith(config.glpi.url)) {
                            imageSessionTokenSolucao = await iniciarSessaoGLPI();
                            if (!imageSessionTokenSolucao) throw new Error("Falha ao obter token de sessão para baixar mídia da solução (interna).");
                        }

                        const imageResponseSolucao = await axios.get(absoluteImageUrlSolucao, {
                            headers: absoluteImageUrlSolucao.startsWith(config.glpi.url) ? 
                                { "App-Token": config.glpi.appToken, "Session-Token": imageSessionTokenSolucao } :
                                { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" },
                            responseType: 'arraybuffer'
                        });
                        
                        // Encerra a sessão GLPI se foi iniciada e usada
                        if (imageSessionTokenSolucao) {
                            await encerrarSessaoGLPI(imageSessionTokenSolucao);
                            imageSessionTokenSolucao = null;
                        }

                        const imageBase64Solucao = Buffer.from(imageResponseSolucao.data, 'binary').toString('base64');
                        const mimeTypeSolucao = imageResponseSolucao.headers['content-type'] || mime.lookup(absoluteImageUrlSolucao) || 'image/jpeg';
                        const dataUriSolucao = `data:${mimeTypeSolucao};base64,${imageBase64Solucao}`;
                        
                        let filenameSolucao = 'solucao.jpg';
                        let descriptiveNameSolucao = "Solução"; // Default descriptive name
                        const altMatchSolucao = htmlContentSolucao.match(/<img[^>]+alt="([^"]+)"[^>]*>/i);
                        if (altMatchSolucao && altMatchSolucao[1] && altMatchSolucao[1].trim()) {
                            descriptiveNameSolucao = altMatchSolucao[1].trim();
                        }

                        filenameSolucao = descriptiveNameSolucao; // Start with alt text as filename base
                        let finalMimeTypeSolucao = imageResponseSolucao.headers['content-type'];
                        const isGlpiDocumentScriptSolucao = absoluteImageUrlSolucao.includes("document.send.php");

                        if (isGlpiDocumentScriptSolucao) {
                            const docIdMatchSolucao = absoluteImageUrlSolucao.match(/docid=(\d+)/);
                            if (docIdMatchSolucao && docIdMatchSolucao[1]) {
                                const docId = docIdMatchSolucao[1];
                                let metadataSessionTokenSolucao = null; 
                                try {
                                    console.log(`ℹ️ Script GLPI (solução) detectado com docid=${docId}. Iniciando sessão para buscar metadados.`);
                                    metadataSessionTokenSolucao = await iniciarSessaoGLPI();
                                    if (!metadataSessionTokenSolucao) {
                                        throw new Error("Falha ao obter token de sessão para metadados do documento GLPI (solução).");
                                    }

                                    const docMetaUrl = `${config.glpi.url}/Document/${docId}`;
                                    console.log(`📄 Buscando metadados de (solução): ${docMetaUrl}`);
                                    const docMetaResponse = await axios.get(docMetaUrl, {
                                        headers: { "App-Token": config.glpi.appToken, "Session-Token": metadataSessionTokenSolucao }
                                    });
                                    if (docMetaResponse.data && docMetaResponse.data.filename && docMetaResponse.data.mime) {
                                        filenameSolucao = docMetaResponse.data.filename;
                                        descriptiveNameSolucao = filenameSolucao; // Atualiza nome descritivo com o da API
                                        finalMimeTypeSolucao = docMetaResponse.data.mime;
                                        console.log(`✅ Metadados do Documento (solução) ID ${docId} obtidos: Nome='${filenameSolucao}', Tipo='${finalMimeTypeSolucao}'`);
                                    } else {
                                        console.warn(`⚠️ Metadados do Documento (solução) ID ${docId} incompletos. Fallback para ALT/Content-Type.`);
                                        finalMimeTypeSolucao = mime.lookup(descriptiveNameSolucao) || imageResponseSolucao.headers['content-type'];
                                    }
                                } catch (docMetaError) {
                                    console.error(`❌ Erro ao buscar metadados do Documento (solução) ID ${docId}: ${docMetaError.message}. Fallback.`);
                                    finalMimeTypeSolucao = mime.lookup(descriptiveNameSolucao) || imageResponseSolucao.headers['content-type'];
                                } finally {
                                    if (metadataSessionTokenSolucao) await encerrarSessaoGLPI(metadataSessionTokenSolucao);
                                    console.log(`ℹ️ Sessão de metadados para docid=${docId} (solução) encerrada.`);
                                }
                            } else {
                                finalMimeTypeSolucao = mime.lookup(descriptiveNameSolucao) || imageResponseSolucao.headers['content-type'];
                            }
                        } else { // Not a GLPI script, rely on Content-Type or alt
                            finalMimeTypeSolucao = imageResponseSolucao.headers['content-type'] || mime.lookup(descriptiveNameSolucao);
                        }
                        
                        const bufferSolucao = Buffer.from(imageResponseSolucao.data, 'binary');
                        const fileTypeInfoSolucao = await fileTypeFromBuffer(bufferSolucao);

                        // Refined Fallback logic for MIME Type
                        if (fileTypeInfoSolucao && fileTypeInfoSolucao.mime && !fileTypeInfoSolucao.mime.includes('unknown')) {
                            finalMimeTypeSolucao = fileTypeInfoSolucao.mime;
                            console.log(`✅ MIME Type para solução determinado por file-type: '${finalMimeTypeSolucao}'`);
                        } else if (!finalMimeTypeSolucao || finalMimeTypeSolucao.includes('unknown') || (finalMimeTypeSolucao.startsWith('text/html') && !isGlpiDocumentScriptSolucao) || finalMimeTypeSolucao === 'application/octet-stream') {
                            
                            console.log(`⚠️ MIME Type atual para solução ('${finalMimeTypeSolucao}') é genérico ou HTML inesperado. Tentando inferir do nome descritivo ('${descriptiveNameSolucao}').`);
                            const mimeFromDescName = mime.lookup(descriptiveNameSolucao);
                            
                            if (mimeFromDescName && !mimeFromDescName.includes('unknown') && !mimeFromDescName.startsWith('text/html') && mimeFromDescName !== 'application/octet-stream') {
                                finalMimeTypeSolucao = mimeFromDescName;
                                console.log(`✅ MIME Type para solução atualizado para '${finalMimeTypeSolucao}' a partir do nome descritivo.`);
                            } else if (finalMimeTypeSolucao && finalMimeTypeSolucao.startsWith('text/html') && (!mimeFromDescName || mimeFromDescName.startsWith('text/html') || mimeFromDescName.includes('unknown') || mimeFromDescName === 'application/octet-stream')) {
                                console.log(`ℹ️ Nome descritivo para solução não forneceu um MIME Type melhor. Mantendo '${finalMimeTypeSolucao}'.`);
                            } else {
                                finalMimeTypeSolucao = 'application/octet-stream';
                                console.log(`ℹ️ MIME Type para solução definido para fallback final: '${finalMimeTypeSolucao}'.`);
                            }
                        }

                        let finalFilenameSolucao = filenameSolucao.replace(/[^a-zA-Z0-9_.-]/g, '_').replace(/\s+/g, '_').replace(/^_+|_+$/g, '');
                        const currentExtSolucao = path.extname(finalFilenameSolucao);
                        const determinedExtSolucao = mime.extension(finalMimeTypeSolucao);
                        if (determinedExtSolucao) {
                            if (currentExtSolucao.toLowerCase() !== `.${determinedExtSolucao.toLowerCase()}`) {
                                if (currentExtSolucao) finalFilenameSolucao = finalFilenameSolucao.substring(0, finalFilenameSolucao.length - currentExtSolucao.length);
                                finalFilenameSolucao += `.${determinedExtSolucao}`;
                            }
                        } else if (!currentExtSolucao && fileTypeInfoSolucao && fileTypeInfoSolucao.ext) {
                            finalFilenameSolucao += `.${fileTypeInfoSolucao.ext}`;
                        } else if (!currentExtSolucao) {
                            finalFilenameSolucao += ".dat";
                        }
                        
                        if (finalFilenameSolucao.startsWith('.') || finalFilenameSolucao.length === 0 || finalFilenameSolucao.toLowerCase() === "solução.dat" || finalFilenameSolucao === "_.dat" || finalFilenameSolucao === "_") {
                            finalFilenameSolucao = `anexo_solucao_${moment().format('HHmmss')}${determinedExtSolucao ? '.' + determinedExtSolucao : '.dat'}`;
                        }

                        if (finalMimeTypeSolucao.startsWith('image/')) {
                            await client.sendImage(sender, dataUriSolucao, finalFilenameSolucao, captionSolucao);
                            console.log(`🖼️ Imagem da solução ('${finalFilenameSolucao}') enviada com legenda para ${sender}.`);
                        } else {
                            const textFallbackSolucao = htmlContentSolucao.replace(/<[^>]*>/g, '').trim();
                            await sendAndLogText(client, sender, `📝 *Solução:* ${textFallbackSolucao}\n📎 (Anexo: '${finalFilenameSolucao}' do tipo '${finalMimeTypeSolucao}' não pôde ser exibido diretamente.)`);
                            console.log(`🚫 Mídia da solução ('${finalFilenameSolucao}', tipo: ${finalMimeTypeSolucao}) não é uma imagem. Enviado como texto/aviso para ${sender}.`);
                        }
                    } catch (error) {
                        console.error(`❌ Erro ao processar mídia da solução para ${sender}: ${error.message}. Detalhes:`, error.response ? error.response.data : '');
                        const textFallbackSolucao = htmlContentSolucao.replace(/<[^>]*>/g, '').trim();
                        if (textFallbackSolucao) await sendAndLogText(client, sender, `📝 *Solução (imagem falhou):* ${textFallbackSolucao}`);
                    } finally {
                        // Garante que a sessão seja fechada se ainda estiver aberta (ex: erro antes do fechamento condicional)
                        if (imageSessionTokenSolucao) {
                            await encerrarSessaoGLPI(imageSessionTokenSolucao);
                        }
                    }
                } else {
                    const solucaoLimpa = htmlContentSolucao.replace(/<[^>]*>/g, '').trim();
                    if (solucaoLimpa) {
                        await sendAndLogText(client, sender, `📝 *Solução:* ${solucaoLimpa}`);
                    }
                }
            }

            if (ticketData.acompanhamento && Array.isArray(ticketData.acompanhamento)) {
                const acompanhamentosInvertidos = [...ticketData.acompanhamento].reverse(); // Cria uma cópia e inverte
                for (const acompanhamentoItem of acompanhamentosInvertidos) {
                    if (acompanhamentoItem) { // Verifica se o item individual não é nulo/vazio
                        const htmlContent = he.decode(acompanhamentoItem);
                        const imgRegex = /<img[^>]+src="([^"]+)"[^>]*>/i; // Case-insensitive regex for img src
                        const imgMatch = htmlContent.match(imgRegex);

                        if (imgMatch && imgMatch[1]) {
                            const imageUrlRelative = imgMatch[1];
                            // Padroniza a obtenção da URL absoluta, igual à da solução
                            const absoluteImageUrl = imageUrlRelative.startsWith('http') ? imageUrlRelative : new URL(imageUrlRelative, config.glpi.url).href;

                            const textContentForCaption = htmlContent.replace(imgRegex, '').replace(/<[^>]*>/g, '').trim();
                            let caption = `👣 *Acompanhamento:* ${textContentForCaption}`;
                            if (caption.length > 1024) caption = caption.substring(0, 1021) + "..."; 

                            let imageSessionToken = null;
                            try {
                                console.log(`👣 Baixando imagem do acompanhamento: ${absoluteImageUrl}`);
                                if (absoluteImageUrl.startsWith(config.glpi.url)) {
                                    imageSessionToken = await iniciarSessaoGLPI();
                                    if (!imageSessionToken) throw new Error("Falha ao obter token de sessão para baixar mídia do acompanhamento (interna).");
                                }

                                const imageResponse = await axios.get(absoluteImageUrl, {
                                    headers: absoluteImageUrl.startsWith(config.glpi.url) ?
                                        { "App-Token": config.glpi.appToken, "Session-Token": imageSessionToken } :
                                        { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" },
                                    responseType: 'arraybuffer'
                                });
                                
                                if (imageSessionToken) {
                                    await encerrarSessaoGLPI(imageSessionToken);
                                    imageSessionToken = null;
                                }

                                const responseContentTypeAcomp = imageResponse.headers['content-type'];
                                console.log(`📄 Content-Type da resposta HTTP para '${absoluteImageUrl}': ${responseContentTypeAcomp}`);
                                
                                let descriptiveNameAcomp = "Acompanhamento";
                                let filenameAcomp = descriptiveNameAcomp; // Initialize filename with default/alt
                                const altMatchAcomp = htmlContent.match(/<img[^>]+alt="([^"]+)"[^>]*>/i);
                                if (altMatchAcomp && altMatchAcomp[1] && altMatchAcomp[1].trim()) {
                                    descriptiveNameAcomp = altMatchAcomp[1].trim();
                                    filenameAcomp = descriptiveNameAcomp;
                                }

                                const isGlpiDocumentScript = absoluteImageUrl.includes("document.send.php");
                                let finalMimeTypeAcomp = responseContentTypeAcomp; // Initialize with response

                                if (isGlpiDocumentScript) {
                                    const docIdMatch = absoluteImageUrl.match(/docid=(\d+)/);
                                    if (docIdMatch && docIdMatch[1]) {
                                        const docId = docIdMatch[1];
                                        let metadataSessionToken = null; 
                                        try {
                                            console.log(`ℹ️ Script GLPI (acompanhamento) detectado com docid=${docId}. Iniciando sessão para buscar metadados.`);
                                            metadataSessionToken = await iniciarSessaoGLPI();
                                            if (!metadataSessionToken) {
                                                throw new Error("Falha ao obter token de sessão para metadados do documento GLPI (acompanhamento).");
                                            }

                                            const docMetaUrl = `${config.glpi.url}/Document/${docId}`;
                                            console.log(`📄 Buscando metadados de (acompanhamento): ${docMetaUrl}`);
                                            const docMetaResponse = await axios.get(docMetaUrl, {
                                                headers: { "App-Token": config.glpi.appToken, "Session-Token": metadataSessionToken }
                                            });
                                            if (docMetaResponse.data && docMetaResponse.data.filename && docMetaResponse.data.mime) {
                                                filenameAcomp = docMetaResponse.data.filename;
                                                finalMimeTypeAcomp = docMetaResponse.data.mime;
                                                console.log(`✅ Metadados do Documento (acompanhamento) ID ${docId} obtidos: Nome='${filenameAcomp}', Tipo='${finalMimeTypeAcomp}'`);
                                            } else {
                                                console.warn(`⚠️ Metadados do Documento (acompanhamento) ID ${docId} incompletos. Fallback para ALT/Content-Type.`);
                                                finalMimeTypeAcomp = mime.lookup(descriptiveNameAcomp) || responseContentTypeAcomp;
                                            }
                                        } catch (docMetaError) {
                                            console.error(`❌ Erro ao buscar metadados do Documento (acompanhamento) ID ${docId}: ${docMetaError.message}. Fallback.`);
                                            finalMimeTypeAcomp = mime.lookup(descriptiveNameAcomp) || responseContentTypeAcomp;
                                        } finally {
                                            if (metadataSessionToken) await encerrarSessaoGLPI(metadataSessionToken);
                                            console.log(`ℹ️ Sessão de metadados para docid=${docId} (acompanhamento) encerrada.`);
                                        }
                                    } else { // GLPI Script but no docid
                                        finalMimeTypeAcomp = mime.lookup(descriptiveNameAcomp) || responseContentTypeAcomp;
                                    }
                                } else {
                                    // Para URLs que não são o script do GLPI, ou se não houver 'alt' útil, usamos o Content-Type da resposta.
                                    finalMimeTypeAcomp = responseContentTypeAcomp || mime.lookup(descriptiveNameAcomp);
                                }

                                const bufferAcomp = Buffer.from(imageResponse.data, 'binary');
                                const fileTypeInfoAcomp = await fileTypeFromBuffer(bufferAcomp);

                                // Fallback final se o MIME type ainda for desconhecido ou genérico
                                if (fileTypeInfoAcomp && fileTypeInfoAcomp.mime && !fileTypeInfoAcomp.mime.includes('unknown')) {
                                    finalMimeTypeAcomp = fileTypeInfoAcomp.mime;
                                    console.log(`✅ MIME Type para acompanhamento determinado por file-type: '${finalMimeTypeAcomp}'`);
                                } else if (!finalMimeTypeAcomp || finalMimeTypeAcomp.includes('unknown') || (finalMimeTypeAcomp.startsWith('text/html') && !isGlpiDocumentScript) || finalMimeTypeAcomp === 'application/octet-stream') {
                                    
                                    console.log(`⚠️ MIME Type atual para acompanhamento ('${finalMimeTypeAcomp}') é genérico ou HTML inesperado. Tentando inferir do nome descritivo ('${descriptiveNameAcomp}').`);
                                    const mimeFromDescName = mime.lookup(descriptiveNameAcomp);
                                    
                                    if (mimeFromDescName && !mimeFromDescName.includes('unknown') && !mimeFromDescName.startsWith('text/html') && mimeFromDescName !== 'application/octet-stream') {
                                        finalMimeTypeAcomp = mimeFromDescName;
                                        console.log(`✅ MIME Type para acompanhamento atualizado para '${finalMimeTypeAcomp}' a partir do nome descritivo.`);
                                    } else if (finalMimeTypeAcomp && finalMimeTypeAcomp.startsWith('text/html') && (!mimeFromDescName || mimeFromDescName.startsWith('text/html') || mimeFromDescName.includes('unknown') || mimeFromDescName === 'application/octet-stream')) {
                                        console.log(`ℹ️ Nome descritivo para acompanhamento não forneceu um MIME Type melhor. Mantendo '${finalMimeTypeAcomp}'.`);
                                    } else {
                                        finalMimeTypeAcomp = 'application/octet-stream';
                                        console.log(`ℹ️ MIME Type para acompanhamento definido para fallback final: '${finalMimeTypeAcomp}'.`);
                                    }
                                }

                                let finalFilenameAcomp = filenameAcomp.replace(/[^a-zA-Z0-9_.-]/g, '_').replace(/\s+/g, '_').replace(/^_+|_+$/g, '');
                                // Garante que o nome do arquivo não seja apenas "." ou ".." ou algo problemático
                                const currentExtAcomp = path.extname(finalFilenameAcomp);
                                const determinedExtAcomp = mime.extension(finalMimeTypeAcomp);
                                if (determinedExtAcomp) {
                                    if (currentExtAcomp.toLowerCase() !== `.${determinedExtAcomp.toLowerCase()}`) {
                                        if (currentExtAcomp) finalFilenameAcomp = finalFilenameAcomp.substring(0, finalFilenameAcomp.length - currentExtAcomp.length);
                                        finalFilenameAcomp += `.${determinedExtAcomp}`;
                                    }
                                } else if (!currentExtAcomp && fileTypeInfoAcomp && fileTypeInfoAcomp.ext) {
                                    finalFilenameAcomp += `.${fileTypeInfoAcomp.ext}`;
                                } else if (!currentExtAcomp) {
                                    finalFilenameAcomp += ".dat";
                                }
                                
                                if (finalFilenameAcomp.startsWith('.') || finalFilenameAcomp.length === 0 || finalFilenameAcomp.toLowerCase() === "acompanhamento.dat" || finalFilenameAcomp === "_.dat" || finalFilenameAcomp === "_") {
                                    finalFilenameAcomp = `anexo_acomp_${moment().format('HHmmss')}${determinedExtAcomp ? '.' + determinedExtAcomp : '.dat'}`;
                                }

                                const imageBase64 = Buffer.from(imageResponse.data, 'binary').toString('base64');
                                const dataUri = `data:${finalMimeTypeAcomp};base64,${imageBase64}`;
                                if (finalMimeTypeAcomp.startsWith('image/')) {
                                    await client.sendImage(sender, dataUri, finalFilenameAcomp, caption);
                                    console.log(`🖼️ Imagem do acompanhamento ('${finalFilenameAcomp}') enviada com legenda para ${sender}.`);
                                } else {
                                    const textContentForFallback = htmlContent.replace(/<[^>]*>/g, '').trim();
                                    await sendAndLogText(client, sender, `👣 *Acompanhamento:* ${textContentForFallback}\n📎 (Anexo: '${descriptiveNameAcomp}' do tipo '${finalMimeTypeAcomp}' não pôde ser exibido diretamente.)`);
                                    console.log(`🚫 Mídia do acompanhamento ('${finalFilenameAcomp}', tipo: ${finalMimeTypeAcomp}) não é uma imagem. Enviado como texto/aviso para ${sender}.`);
                                }
                            } catch (error) {
                                console.error(`❌ Erro ao processar mídia do acompanhamento para ${sender}: ${error.message}. Detalhes:`, error.response ? error.response.data : '');
                                const textFallback = htmlContent.replace(/<[^>]*>/g, '').trim();
                                if (textFallback) await sendAndLogText(client, sender, `👣 *Acompanhamento (imagem falhou):* ${textFallback}`);
                            } finally {
                                if (imageSessionToken) {
                                    await encerrarSessaoGLPI(imageSessionToken);
                                }
                            }
                        } else {
                            const acompanhamentoLimpo = htmlContent.replace(/<[^>]*>/g, '').trim();
                            if (acompanhamentoLimpo) {
                                await sendAndLogText(client, sender, `👣 *Acompanhamento:* ${acompanhamentoLimpo}`);
                            }
                        }
                    }
                }
            }
            // Envia o menu como uma mensagem separada
            await sendAndLogText(client, sender, "Como posso te ajudar agora?\n1️⃣ Abrir novo chamado\n2️⃣ Acompanhar outro chamado\n0️⃣ Encerrar");
        } else {
            await sendAndLogText(client, sender, `❌ Não foi possível encontrar informações para o chamado *#${ticketId}*.`);
            await sendAndLogText(client, sender, "Como posso te ajudar agora?\n1️⃣ Abrir novo chamado\n2️⃣ Acompanhar outro chamado\n0️⃣ Encerrar");
        }
        estadoUsuario[sender].estado = "aguardando_opcao_inicial";
    }
     else {
        console.warn(`⚠️ Estado não reconhecido ou fluxo quebrado para ${sender}: ${currentState}. Redefinindo.`);
        const sessionPathToClean = estadoUsuario[sender]?.dadosTemporarios?.attachmentSessionPath;
        await sendAndLogText(client, sender, "❌ Ops! Algo não saiu como esperado. Vamos recomeçar.");
        delete usuariosAtendidos[sender]; delete estadoUsuario[sender];
        await limparPastaSessaoAnexos(sessionPathToClean);
        if (timeoutSessoes[sender]) clearTimeout(timeoutSessoes[sender]); delete timeoutSessoes[sender];
        return; 
    }
    reiniciarTimerInatividade(client, sender);
}

// ==============================================
// INICIALIZAÇÃO DO SERVIDOR
// ==============================================

const PORT = process.env.PORT || 3000;

function startServer(portToTry) {
    const server = app.listen(portToTry, () => {
        console.log(`🌐 Servidor web rodando na porta ${portToTry}`);
        console.log(`Acesse a interface em: http://localhost:${portToTry}/`); 
        server.on('upgrade', (request, socket, head) => {
            wss.handleUpgrade(request, socket, head, ws => wss.emit('connection', ws, request));
        });
        wss.on('connection', (ws) => {
            console.log('🔌 Cliente WebSocket conectado à interface web.');
            broadcastStatus(); 
             ws.send(JSON.stringify({ 
                type: 'glpiConfigStatus',
                data: {
                    configured: !!(config.glpi?.url && config.glpi?.appToken && config.glpi?.userToken),
                    requireLogin: config.auth.requireLogin
                }
            }));
            ws.on('message', message => console.log('📦 Mensagem do WebSocket:', message.toString()));
            ws.on('close', () => console.log('🔌 Cliente WebSocket desconectado.'));
            ws.on('error', (error) => console.error('❌ Erro no WebSocket:', error));
        });

        console.log("⏳ Verificando configuração do GLPI antes de iniciar o bot...");
        setTimeout(() => {
            if (config.glpi && config.glpi.url && config.glpi.appToken && config.glpi.userToken) {
                console.log("🚀 Configuração do GLPI encontrada. Iniciando o bot WhatsApp...");
                iniciarBot(1); 
            } else {
                console.warn("⚠️ Bot WhatsApp não iniciado: Configuração do GLPI está incompleta.");
                broadcastLog("Bot não iniciado: Configuração do GLPI incompleta.", "warn");
                iniciarBot(1); 
            }
        }, 5000); 
    }).on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.warn(`⚠️ Porta ${portToTry} em uso, tentando porta ${portToTry + 1}...`);
            startServer(portToTry + 1); 
        } else {
            console.error('❌ Erro fatal ao iniciar servidor web:', err);
            process.exit(1); 
        }
    });
}

startServer(parseInt(PORT, 10));
