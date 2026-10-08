**ArcanaFutura** é uma aplicação web de leitura de Tarot com inteligência artificial. A pessoa escreve uma intenção (opcional), escolhe quantas cartas quer tirar (1, 3 ou 5), vira as cartas de um baralho embaralhado dos Arcanos Maiores e recebe uma leitura gerada pelo Google Gemini, entregue ao navegador em tempo real via WebSockets. Depois, ainda dá para conversar com o "tarólogo" sobre a leitura.

Foi meu projeto final do curso **CS50 de Harvard** e, depois, passou por uma **auditoria completa de QA e segurança**: mais de 300 casos de teste manuais, cerca de 40 defeitos encontrados, 5 deles críticos, todos corrigidos e protegidos por uma suíte automatizada de Pytest que roda no CI a cada commit.

**🔗 [App no ar](https://arcanafutura.onrender.com)** · **📊 [Matriz completa de testes](https://docs.google.com/spreadsheets/d/1o8hVff3aoBEdNZ48j4oaW1-oXteNvpU7OzxkRuL8xvc/edit?usp=sharing)**

---

## Como funciona

```
/ (home)  ──►  /process_form (POST, JSON)  ──►  /cartas  ──►  /results (POST)  ──►  WebSocket
 intenção        valida + sanitiza               escolhe N cartas   renderiza a página   start_generation ──► Gemini ──► generation_complete
 + nº cartas     guarda na sessão (Redis)        (animação de flip)                      send_message     ──► Gemini ──► receive_message
```

1. **Home (`/`)**: a pessoa digita a intenção (máx. 400 caracteres, pode ficar vazia) e escolhe 1, 3 ou 5 cartas. O formulário é enviado com `fetch()` para `/process_form`, que valida, sanitiza tudo e devolve um redirect em JSON.
2. **Seleção de cartas (`/cartas`)**: o baralho de 22 cartas é embaralhado no servidor e cada carta recebe uma orientação aleatória (`normal` ou `invertido`). O navegador vira as cartas uma a uma (transformações 3D em CSS), move as escolhidas para um "palco" e envia para `/results`.
3. **Resultado (`/results`)**: a página renderiza na hora. A leitura em si é gerada **de forma assíncrona**, depois do carregamento, por um evento Socket.IO, então a requisição HTTP nunca fica presa esperando o LLM.
4. **Leitura e chat**: o servidor chama o Gemini em uma tarefa de segundo plano, guarda a leitura em cache no Redis (quem reconecta recebe na hora) e envia o resultado para o socket correto. O chat de acompanhamento reaproveita a leitura como contexto.
5. **Proteção de privacidade**: uma checagem com `sessionStorage` chama `/clear_session` quando a página é aberta em uma aba nova, para que a sessão de uma pessoa não seja herdada por outra em computadores compartilhados.

## Stack

| Camada | Ferramentas |
|---|---|
| **Backend** | Python, Flask, Jinja2, Flask-SocketIO (gevent), Gunicorn |
| **Estado** | Redis (sessões no servidor, cache da leitura, histórico do chat, contadores de rate limit) |
| **IA** | Google Gemini API (`google-generativeai`, modelo `gemini-3.1-flash-lite`), pipeline Markdown → HTML |
| **Segurança** | Flask-WTF (CSRF), Flask-Talisman (CSP e headers de segurança), Flask-Limiter, Bleach, ProxyFix |
| **Frontend** | JavaScript puro (DOM, Web Animations API, `sessionStorage`), HTML/CSS, marcação pensada para acessibilidade (WCAG) |
| **QA / CI** | Pytest, Bandit (SAST), GitHub Actions, pre-commit, DevTools, cURL, RedisInsight, Lighthouse, BrowserStack |
| **Hospedagem** | Render (atrás de proxy reverso Render/Cloudflare) |

## Medidas de segurança

- **Proteção CSRF** em todas as rotas HTTP que alteram estado, e `validate_csrf()` manual nos eventos WebSocket (que não passam pelo middleware do Flask).
- **Sanitização de entrada**: todo texto do usuário tem o HTML removido com Bleach (política de texto puro) e tem limite de tamanho (400 caracteres na intenção, 500 nas mensagens do chat).
- **Escape em contexto JS**: valores renderizados dentro de blocos `<script>` usam `| tojson`, já que sanitizadores de HTML não protegem contra quebra de string em JavaScript.
- **Content Security Policy** com nonce por requisição via Talisman. Origens de desenvolvimento (BrowserSync, localhost) só entram quando `is_production` é falso.
- **Rate limiting**:
  - HTTP: Flask-Limiter com Redis, mais restrito em `/results` em produção (5/min) para proteger a cota do Gemini.
  - WebSocket: limitador próprio de janela deslizante (10 mensagens por 60 s por sessão), porque o Flask-Limiter não enxerga eventos de socket.
- **Sessão reforçada**: sessões no Redis, ID assinado, `HttpOnly`, `SameSite=Lax`, `Secure` em produção, vida útil de 30 minutos e cookie não permanente.
- **CORS**: origens do Socket.IO restritas ao domínio de produção.
- **Proxy reverso**: `ProxyFix(x_for=1, …)` corresponde à arquitetura de um salto da Render, então o IP real do cliente é usado e headers `X-Forwarded-For` forjados não são confiados.
- **Erros tratados**: rotas inexistentes redirecionam para a home; payloads malformados ou adulterados caem em valores seguros em vez de gerar erro 500.

## Destaques da auditoria de QA

A auditoria foi organizada em hierarquia Scrum no Jira: **9 Épicos → 54 User Stories → mais de 300 subtarefas**, executadas principalmente com testes exploratórios manuais. Para decidir o que automatizar, usei uma única pergunta:

> *"Se isso quebrar, o app vai travar, ser hackeado ou me custar dinheiro?"*

Validações visuais e de animação ficaram manuais. Portões de segurança, proteções da cota da API e lógica de rotas viraram testes Pytest.

Cinco achados críticos foram documentados em profundidade e corrigidos:

| # | Achado | Camada | Correção |
|---|---|---|---|
| 1 | **Mutação do baralho global**: o embaralhamento escrevia orientações direto em `TAROT_CARDS`, corrompendo o estado sob requisições gevent concorrentes | Runtime do Flask | `deck_copy = [card.copy() for card in TAROT_CARDS]` |
| 2 | **Bypass do rate limiter** com `X-Forwarded-For` forjado (`ProxyFix` mal configurado) | Fronteira do proxy | `ProxyFix(x_for=1, …)` |
| 3 | **Cross-Site WebSocket Hijacking**: sem CSRF no `send_message` e CORS com curinga, permitindo drenar a cota do Gemini de graça | WebSocket (entrada) | `validate_csrf()`, lista de origens permitidas e limitador próprio |
| 4 | **Quebra de contexto JS**: `{{ intencao }}` dentro de `<script>`; o Bleach não protege nesse contexto | Renderizador Jinja2 | `{{ intencao \| tojson }}` |
| 5 | **Dead SID**: emitir para `session.sid` (chave do Redis) em vez de `request.sid` (sala do socket) causava loading infinito e consumo silencioso de cota | WebSocket (saída) | Usar `request.sid` + cache da leitura no Redis para reconexões |

👉 O detalhamento completo (impacto, correção e teste de regressão de cada achado) está no meu portfólio.

## Suíte de testes automatizados

Os testes são organizados por Épico de QA. O docstring de cada teste explica o **risco** que ele protege (crash, ataque ou custo), então a suíte também funciona como documentação.

| Arquivo | Escopo |
|---|---|
| `test_epic_1.py` | Fluxo do formulário, validação no backend, sanitização XSS, CSRF, limites de tamanho, métodos HTTP |
| `test_epic_2.py` | Embaralhamento e imutabilidade do baralho, contador de seleção, resiliência do payload de `/results` |
| `test_epic_3.py` | Pipeline de geração com IA, integridade do prompt, tratamento de falhas |
| `test_epic_4.py` | Segurança do handler de chat, fallback em falhas de WebSocket |
| `test_epic_5.py` | Rate limiting, flags de cookie, CSRF no WebSocket, isolamento de sessão |
| `test_epic_6.py` | Rota `/clear_session` (apenas POST, isenta de CSRF, limpa tudo) |
| `test_epic_7.py` | Guardas de navegação e de sessão, tratamento de 404 |
| `test_epic_8.py` | Headers de segurança, CORS, configuração de CSP |

Os Épicos 6 (comportamento visual e de toque) e 9 (cross-browser, acessibilidade e performance) são em grande parte **manuais por decisão**: exigem um navegador real, e o lugar certo para isso é Playwright ou Cypress, não um runner de testes unitários.

**Padrão interessante: `xfail` como correção guiada por testes.** Vulnerabilidades conhecidas foram escritas primeiro como testes `@pytest.mark.xfail(strict=True)`: ficam vermelhos enquanto o bug existe, documentando o problema com um caso reproduzível, e viram verdes quando a correção entra.

## Pipeline de CI

O workflow `.github/workflows/ci.yml` roda a cada push e pull request na `main`:

1. Sobe um serviço **Redis** no runner (`ubuntu-latest`).
2. Instala o **Python 3.11** e as dependências.
3. Roda o **Bandit** (`bandit -lll -r . -x ./tests`) para análise estática de segurança, com o mesmo nível de severidade usado localmente.
4. Executa o **Pytest** com as variáveis de ambiente de teste.

## Estrutura do projeto

```
.
├── .github/workflows/ci.yml     # Pipeline de CI (Pytest + Bandit)
├── .pre-commit-config.yaml
├── app.py                       # App Flask, rotas, handlers Socket.IO, configuração de segurança
├── start.sh                     # Entrypoint de produção (Gunicorn + worker gevent-websocket)
├── Procfile
├── requirements.txt
├── LICENSE
├── static/
│   ├── styles.css
│   ├── img/                     # Arte das cartas (a01–a22), versos e decorações
│   └── js/
│       ├── index.js
│       ├── cartas.js
│       └── results.js
├── templates/
│   ├── layout.html              # Template base (navbar, decorações, fontes)
│   ├── index.html               # Formulário de intenção + número de cartas
│   ├── cartas.html              # Tabuleiro de seleção de cartas
│   └── results.html             # Leitura + interface de chat
└── tests/
    ├── conftest.py              # Fixtures: client, csrf_client, socket_client
    └── test_epic_1.py … test_epic_8.py
```

## Rodando localmente

**Pré-requisitos:** Python 3.11, Redis rodando em `localhost:6379` (ou uma `REDIS_URL`) e uma chave de API do [Google AI Studio](https://aistudio.google.com/).

```bash
# 1. Clonar
git clone https://github.com/akaselvas/cs50_arcanafutura.git
cd cs50_arcanafutura

# 2. Criar ambiente virtual
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Instalar dependências
pip install -r requirements.txt

# 4. Criar o arquivo .env (veja a seção abaixo)

# 5. Subir o Redis (exemplo com Docker)
docker run -d -p 6379:6379 redis

# 6. Rodar o app
python app.py
```

Depois, acesse <http://localhost:5000>.

Em desenvolvimento (`RENDER` não definida), o rate limiting fica desligado, a CSP aceita ferramentas locais de dev e o Socket.IO aceita qualquer origem.

Para rodar os testes (com Redis no ar e as variáveis de ambiente definidas):

```bash
pytest -v
```

## Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|---|---|---|
| `SECRET_KEY` | ✅ | Assina sessões e tokens CSRF. O app não inicia sem ela. |
| `GENAI_API_KEY` | ✅ | Chave da API do Google Gemini. O app não inicia sem ela. |
| `REDIS_URL` | ❌ | Padrão: `redis://localhost:6379`. |
| `RENDER` | ❌ | Definida automaticamente pela Render; ativa o modo produção (cookies `Secure`, CORS restrito, rate limiting ligado). |

Exemplo de `.env`:

```env
SECRET_KEY=troque-por-uma-string-longa-e-aleatoria
GENAI_API_KEY=sua-chave-do-gemini
REDIS_URL=redis://localhost:6379
```

## Deploy

O app roda na **Render**, com uma instância Redis gerenciada. Comando de início em produção (`start.sh`):

```bash
gunicorn -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 --timeout 120 app:app -b 0.0.0.0:$PORT
```

Um único worker é proposital: o limitador do chat é em memória (para não esgotar o pool de conexões do Redis, que é limitado), então ele não é compartilhado entre workers.

## Licença

Veja o arquivo [LICENSE](LICENSE).

---

> **Nota de transparência:** o código dos testes automatizados foi escrito em colaboração com ferramentas de IA. Eu defini a estratégia de testes, encontrei os casos de borda por testes exploratórios manuais e revisei todo o código gerado contra o código-fonte da aplicação.