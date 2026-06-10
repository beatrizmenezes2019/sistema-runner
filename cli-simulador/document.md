# CLI do Simulador HubSaúde

Esta ferramenta permite **iniciar, parar e verificar** o servidor simulador do HubSaúde diretamente pelo terminal, sem precisar baixar ou configurar nada manualmente.

> Funciona em **Windows**, **Linux** e **macOS**.

---

## O que é o simulador?

O simulador reproduz o comportamento do servidor HubSaúde em ambiente local, permitindo testar integrações sem acessar o ambiente de produção. É a ferramenta ideal para desenvolvimento e testes.

---

## Instalação

### 1. Baixe o executável

Acesse a aba [**Releases**](../../releases) do repositório e baixe o arquivo correto para o seu sistema:

| Sistema | Arquivo para baixar |
|---|---|
| Windows | `cli-simulador-*-windows-amd64.exe` |
| Linux | `cli-simulador-*-linux-amd64` |
| macOS | `cli-simulador-*-darwin-amd64` |

### 2. Verifique a integridade do arquivo (recomendado)

Antes de usar, confirme que o arquivo não foi corrompido durante o download:

```bash
# Verificar checksum SHA-256
sha256sum -c SHA256SUMS.txt

# Verificar assinatura Cosign (requer cosign instalado — https://docs.sigstore.dev/cosign/system_config/installation/)
cosign verify-blob \
  --signature cli-simulador-v1.0.0-linux-amd64.sig \
  --certificate cli-simulador-v1.0.0-linux-amd64.pem \
  --certificate-identity-regexp "https://github.com/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  cli-simulador-v1.0.0-linux-amd64
```

Os arquivos `.sig` e `.pem` de cada executável estão disponíveis na mesma página de Releases. As assinaturas são geradas automaticamente no CI via [Sigstore Cosign](https://sigstore.dev/) — sem chave privada manual.

### 3. Nada mais é necessário!

- **O arquivo do simulador é baixado automaticamente** na primeira vez que você executar o comando `start`, com verificação de integridade SHA-256.
- **Java é instalado automaticamente** caso não esteja presente no seu computador.

---

## Como usar

Abra o terminal (Prompt de Comando no Windows, Terminal no Linux/macOS) na pasta onde salvou o executável.

---

### Iniciar o simulador (`start`)

Liga o servidor do simulador em background. O comando aguarda o servidor ficar completamente pronto antes de retornar.

```bash
# No Windows
.\simulador.exe start

# No Linux / macOS
./simulador start
```

**Com porta personalizada:**
```bash
.\simulador.exe start --port 9090
```

**O que acontece automaticamente:**

1. Verifica se o Java está instalado — se não estiver, baixa e configura o Java 21 Temurin.
2. Verifica se o arquivo do simulador existe em `~/.hubsaude/` — se não existir, faz o download com verificação de integridade SHA-256.
3. Verifica se o simulador já está rodando com um **health check real** em `/health` — se estiver, reaproveita a instância existente.
4. Inicia o servidor e aguarda até que esteja pronto para receber requisições (timeout de 30 segundos).

**Exemplo de saída:**
```
[info] Simulador iniciado (PID 12345). Aguardando readiness na porta 8080...
[info] Simulador pronto e respondendo na porta 8080.
```

---

### Verificar o estado do simulador (`status`)

Mostra se o simulador está rodando e respondendo normalmente.

```bash
.\simulador.exe status
.\simulador.exe status --port 9090
```

**Possíveis resultados:**

```
STATUS: PRONTO
  PID   : 12345
  Porta : 8080
  Health: OK (http://localhost:8080/health)
```

```
STATUS: PROCESSO EM EXECUÇÃO, MAS NÃO RESPONDE
  PID   : 12345
  Porta : 8080
  Health: FALHOU
  Dica  : O simulador pode estar ainda inicializando. Aguarde ou execute 'simulador stop' e tente novamente.
```

```
STATUS: PARADO
  Nenhuma instância registrada em ~/.hubsaude/simulador.pid
```

---

### Parar o simulador (`stop`)

Encerra o servidor do simulador que está rodando em background.

```bash
.\simulador.exe stop
```

**Exemplo de saída:**
```
[info] Simulador (PID 12345) encerrado com sucesso.
```

---

### Ver a versão instalada (`version`)

```bash
.\simulador.exe version
# Exemplo de saída: simulador v1.2.0 (commit abc1234)
```

---

## Opções globais

| Opção | O que faz |
|---|---|
| `--verbose` | Exibe informações extras de diagnóstico no formato `key=value` — útil para entender o que está acontecendo em caso de erro |

---

## Verificação de integridade do JAR

Ao baixar o JAR do simulador, a ferramenta verifica automaticamente a integridade comparando o SHA-256 do arquivo com o checksum publicado na página de releases. Se os hashes divergirem, o download é rejeitado com uma mensagem explicativa — o arquivo corrompido nunca chega a ser usado.

Se o arquivo de checksum remoto não estiver disponível (ex.: sem conexão), a ferramenta emite um aviso e prossegue o download. Um aviso de diagnóstico fica visível com `--verbose`:

```
time=... level=WARN msg="arquivo de checksum não disponível, continuando sem verificação" error="..."
```

---

## Diagnóstico com `--verbose`

A opção `--verbose` ativa o nível `DEBUG` do logging estruturado (`slog`). As mensagens são emitidas para `stderr` no formato:

```
time=2025-06-30T12:00:00.000Z level=DEBUG msg="JAR do simulador encontrado" path=/home/user/.hubsaude/hubsaude-validador-api.jar
time=2025-06-30T12:00:00.001Z level=DEBUG msg="Executando" java=/usr/bin/java args="-jar ... --server.port=8080"
time=2025-06-30T12:00:00.002Z level=DEBUG msg="SHA-256 verificado" hash=abc123...
```

Sem `--verbose`, apenas mensagens de nível `INFO` e acima são exibidas.

---

## Arquivos gerados automaticamente

O simulador utiliza a pasta `~/.hubsaude/` para guardar seus arquivos:

| Arquivo | O que é |
|---|---|
| `~/.hubsaude/hubsaude-validador-api.jar` | O servidor do simulador (baixado automaticamente com verificação SHA-256) |
| `~/.hubsaude/simulador.pid` | O número identificador do processo em execução |
| `~/.hubsaude/simulador.log` | O registro de saída do simulador |
| `~/.hubsaude/jdk/` | O Java instalado automaticamente (se necessário) |

> No Windows, `~` equivale à pasta do seu usuário, por exemplo: `C:\Users\seu-nome\.hubsaude\`

---

## O que fazer se algo der errado

**"Java não encontrado" / download falhou**
A ferramenta tenta instalar o Java 21 Temurin automaticamente. Se o download falhar (ex.: sem internet), instale o Java 21 manualmente em [adoptium.net](https://adoptium.net/).

**"Verificação de integridade do JAR falhou"**
O arquivo baixado não corresponde ao checksum esperado. Isso pode indicar falha de rede ou arquivo corrompido. Remova `~/.hubsaude/hubsaude-validador-api.jar` e execute `simulador start` novamente para um novo download.

**O simulador não fica pronto / timeout**
Execute `simulador status` para ver o estado atual. Se necessário, rode `simulador stop` e tente `simulador start` novamente. Verifique também se a porta 8080 não está sendo usada por outro programa com `simulador start --port 9090`.

**"Nenhuma instância registrada"**
O simulador não está rodando. Use `simulador start` para iniciá-lo.

---

## Fluxo típico de uso

```bash
# 1. Inicie o simulador
./simulador start

# 2. Verifique se está pronto
./simulador status

# 3. Use o simulador para seus testes...
#    (o servidor responde em http://localhost:8080)

# 4. Ao terminar, pare o simulador
./simulador stop
```

---

## Para desenvolvedores

### Compilar localmente

```bash
cd cli-simulador
go build -o simulador ./cmd/simulador/main.go
```

### Executar os testes

```bash
go test ./... -v -coverprofile=coverage.out
go tool cover -html=coverage.out   # relatório visual de cobertura
```

### Lint

```bash
golangci-lint run
```

O lint é executado automaticamente no CI e bloqueia o build em caso de violações. A configuração está em `.golangci.yml`.
