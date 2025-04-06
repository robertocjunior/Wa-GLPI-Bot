# Wa-GLPI-Bot

<img src="app/public/GLPI-WA.png" alt="Archon Logo" />

<div align="center" style="margin-top: 20px;margin-bottom: 30px">

## Visão Geral

O **Wa-GLPI-Bot** é um sistema que integra o WhatsApp com o GLPI (Gerenciador Livre de Parque Informatizado), permitindo:

- Abertura de chamados no GLPI via WhatsApp
- Acompanhamento de chamados existentes
- Interface web para configuração e monitoramento

---

## Pré-requisitos

- Docker instalado  
- Docker Compose (opcional, mas recomendado)  
- Acesso a uma instância GLPI com API REST habilitada  

---

## Métodos de Instalação

### 1. Usando Docker Compose (recomendado)

Crie um arquivo `docker-compose.yml` com o seguinte conteúdo:

```yaml
version: '3'
services:
  wa-glpi-bot:
    image: robertocjunior/wa-glpi-bot:latest
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - ./data:/app/data
    environment:
      - NODE_ENV=production
```

Em seguida, execute:

```bash
docker-compose up -d
```

---

### 2. Usando Docker diretamente

```bash
docker run -d \
  --name wa-glpi-bot \
  -p 3000:3000 \
  -v ./data:/app/data \
  robertocjunior/wa-glpi-bot:latest
```

---

### 3. Build a partir do repositório GitHub

```yaml
version: '3'
services:
  wa-glpi-bot:
    build:
      context: https://github.com/robertocjunior/Wa-GLPI-Bot.git
    command: >
      sh -c "npm install && npm run start"
    working_dir: /home/node/app
    environment:
      - NODE_ENV=production
    ports:
      - "3000:3000"
```

---

## Configuração Inicial

Acesse a interface web em:  
`http://seu-servidor:3000/login`

Use as credenciais padrão:

- **Usuário:** admin  
- **Senha:** admin

---

## Configurando o GLPI

Na aba **"Configuração da API"**, preencha:

- **URL do GLPI** (ex: `http://glpi.example.com/apirest.php`)
- **App Token** (gerado no GLPI)
- **User Token** (gerado no GLPI)

Clique em **"Salvar Configurações"**

---

## Alterando a senha padrão

Na aba **"Alterar Senha"**:

1. Insira a nova senha (mínimo 8 caracteres)  
2. Confirme a nova senha  
3. Digite a senha atual (admin inicialmente)  
4. Clique em **"Alterar Senha"**

---

## Uso do Bot no WhatsApp

- O bot irá gerar um QR Code no console (aba **"Console do Sistema"**)  
- Escaneie o QR Code com o WhatsApp que será usado como bot  

### Interaja com o bot usando os seguintes comandos:

#### Menu principal:

```
1️⃣ - Abrir chamado  
2️⃣ - Acompanhar chamado  
0️⃣ - Sair  
```

#### Abrir chamado:

- Descreva brevemente o problema  
- Forneça detalhes adicionais  
- Envie anexos (opcional)  
- Informe seu nome  

#### Acompanhar chamado:

- Informe o número do chamado  
- Receba informações sobre status e técnico responsável  

#### Encerrar sessão:

- Digite `#` a qualquer momento para encerrar  

---

## Monitoramento

A aba **"Console do Sistema"** mostra:

- Logs de operação  
- Status da conexão com o WhatsApp  
- QR Codes para autenticação  
- Erros e avisos  

---

## Gerenciamento de Sessões

- Sessões inativas por 60 minutos são encerradas automaticamente  
- O bot mantém estado da conversa para cada usuário  

---

## Variáveis de Ambiente

| Variável   | Descrição                  | Padrão      |
|------------|----------------------------|-------------|
| NODE_ENV   | Ambiente de execução       | production  |
| PORT       | Porta para a interface web | 3000        |

---

## Volumes

O container utiliza um volume para persistir:

- Configurações do sistema  
- Arquivos temporários  
- Dados de sessão  

> Mapeie para `./data` no host (como no exemplo do Docker Compose) para persistência.

---

## Solução de Problemas

### Bot não conecta ao WhatsApp:

- Verifique os logs no console  
- Escaneie novamente o QR Code se expirar  
- Reinicie o container se necessário  

### Erros na API do GLPI:

- Verifique as credenciais e URL  
- Confira se a API REST está habilitada no GLPI  
- Verifique permissões do usuário no GLPI  

### Problemas de autenticação:

- Se esquecer a senha, delete o arquivo `glpi_config.json` no volume para resetar para as credenciais padrão  

---

## Atualização

### Com Docker Compose:

```bash
docker-compose pull
docker-compose up -d
```

### Usando Docker diretamente:

```bash
docker pull robertocjunior/wa-glpi-bot:latest
docker stop wa-glpi-bot
docker rm wa-glpi-bot
docker run -d ... # com os mesmos parâmetros anteriores
```

---

## Segurança

- Altere a senha padrão imediatamente após a instalação  
- Exponha a porta 3000 apenas em redes confiáveis  
- Considere usar HTTPS via proxy reverso se acessível pela internet  

---

## Contribuição

Contribuições são bem-vindas no repositório GitHub:  
[https://github.com/robertocjunior/Wa-GLPI-Bot](https://github.com/robertocjunior/Wa-GLPI-Bot)
```
