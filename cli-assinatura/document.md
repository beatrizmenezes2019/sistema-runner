# CLI de Assinatura Digital

Esta ferramenta permite **criar e validar assinaturas digitais** em documentos de saúde diretamente pelo terminal, sem precisar saber programar em Java ou instalar nada manualmente.

> Funciona em **Windows**, **Linux** e **macOS**.

---

## Instalação

### 1. Baixe o executável

Acesse a aba [**Releases**](../../releases) do repositório e baixe o arquivo correto para o seu sistema:

| Sistema | Arquivo para baixar |
|---|---|
| Windows | `cli-assinatura-*-windows-amd64.exe` |
| Linux | `cli-assinatura-*-linux-amd64` |
| macOS | `cli-assinatura-*-darwin-amd64` |

### 2. Verifique a integridade do arquivo (recomendado)

Antes de usar, confirme que o arquivo não foi corrompido durante o download:

```bash
# Verificar checksum SHA-256
sha256sum -c SHA256SUMS.txt

# Verificar assinatura Cosign (requer cosign instalado — https://docs.sigstore.dev/cosign/system_config/installation/)
cosign verify-blob \
  --signature cli-assinatura-v1.0.0-linux-amd64.sig \
  --certificate cli-assinatura-v1.0.0-linux-amd64.pem \
  --certificate-identity-regexp "https://github.com/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  cli-assinatura-v1.0.0-linux-amd64
```

Os arquivos `.sig` e `.pem` de cada executável estão disponíveis na mesma página de Releases. As assinaturas são geradas automaticamente no CI via [Sigstore Cosign](https://sigstore.dev/) — sem chave privada manual.

### 3. Baixe o motor de assinatura

Na mesma página de Releases, baixe também o arquivo `assinador.jar` e coloque-o na mesma pasta que o executável, **ou** em `~/.hubsaude/assinador.jar`.

### 4. Java é opcional

Se o seu computador não tiver Java instalado, não se preocupe — a ferramenta **baixa e configura o Java 21 Temurin automaticamente** na primeira vez que precisar dele.

---

## Como usar

Abra o terminal (Prompt de Comando no Windows, Terminal no Linux/macOS) na pasta onde salvou o executável.

### Assinar um documento (`sign`)

Cria uma assinatura digital para um par de arquivos de documento de saúde.

```bash
# No Windows
.\assinatura.exe sign \
  --bundle    "C:\documentos\bundle.json" \
  --provenance "C:\documentos\provenance.json" \
  --config    "{}" \
  --cert      "C:\documentos\certificado.cer" \
  --timestamp 1751328000 \
  --estrategia "AD_RB" \
  --pid       "https://minha-politica.exemplo.gov.br|0.0.1"

# No Linux / macOS
./assinatura sign \
  --bundle     ./documentos/bundle.json \
  --provenance ./documentos/provenance.json \
  --config     '{}' \
  --cert       ./documentos/certificado.cer \
  --timestamp  1751328000 \
  --estrategia AD_RB \
  --pid        "https://minha-politica.exemplo.gov.br|0.0.1"
```

**O que cada parâmetro significa:**

| Parâmetro | O que informar |
|---|---|
| `--bundle` | Caminho para o arquivo `bundle.json` (o documento principal a ser assinado) |
| `--provenance` | Caminho para o arquivo `provenance.json` (metadados sobre quem gerou o documento) |
| `--config` | Configuração do material criptográfico — em modo simulado, use `{}`; para token físico, veja [Usando com token físico (PKCS#11)](#usando-com-token-físico-pkcs11) |
| `--cert` | Caminho para o arquivo de certificado digital (`.cer` ou `.der`) |
| `--timestamp` | Data/hora da assinatura no formato Unix (número inteiro — ex.: `1751328000`) |
| `--estrategia` | Estratégia de carimbo de tempo (ex.: `AD_RB`, `AD_RT`) |
| `--pid` | Identificador da política de assinatura |

**Resultado esperado:** o terminal exibirá um objeto JSON com `"resourceType": "Signature"` contendo a assinatura gerada.

---

### Validar uma assinatura (`validate`)

Verifica se uma assinatura digital é válida.

```bash
# No Windows
.\assinatura.exe validate \
  --jws    "CONTEUDO_DA_ASSINATURA_AQUI" \
  --config "{\"trustStore\":[]}"

# No Linux / macOS
./assinatura validate \
  --jws    "CONTEUDO_DA_ASSINATURA_AQUI" \
  --config '{"trustStore":[]}'
```

**O que cada parâmetro significa:**

| Parâmetro | O que informar |
|---|---|
| `--jws` | O conteúdo da assinatura gerada pelo comando `sign` (o valor do campo `data` dentro do JSON de resposta) |
| `--config` | Configuração de validação em JSON. O campo `trustStore` lista os certificados confiáveis |

**Resultado esperado:** JSON indicando `"Assinatura validada com sucesso"` ou uma mensagem explicando o problema encontrado.

---

### Iniciar o motor de assinatura como serviço (`start`)

Sobe o `assinador.jar` em background como um servidor HTTP. Útil quando você vai fazer várias assinaturas seguidas — o servidor fica pronto e responde mais rápido.

```bash
.\assinatura.exe start               # porta padrão: 8080
.\assinatura.exe start --port 9090   # porta personalizada
```

O comando realiza um **health check real** antes de retornar — só declara o servidor pronto após receber `200 OK` em `/health`. Se a porta já estiver em uso por outro serviço (que não o assinador), a ferramenta detecta isso e informa ao usuário.

---

### Verificar se o serviço está rodando (`status`)

```bash
.\assinatura.exe status
.\assinatura.exe status --port 9090
```

---

### Parar o serviço (`stop`)

```bash
.\assinatura.exe stop
.\assinatura.exe stop --port 9090
```

---

### Ver a versão instalada (`version`)

```bash
.\assinatura.exe version
# Exemplo de saída: assinatura v1.2.0 (commit abc1234)
```

---

## Opções globais

| Opção | O que faz |
|---|---|
| `--jar <caminho>` | Indica onde está o arquivo `assinador.jar`, caso não esteja na pasta padrão |
| `--verbose` | Exibe informações extras de diagnóstico no formato `key=value` — útil para entender o que está acontecendo em caso de erro |

---

## Localização automática do `assinador.jar`

A ferramenta procura o arquivo `assinador.jar` automaticamente nos seguintes lugares, nesta ordem:

1. Caminho indicado com `--jar`
2. Variável de ambiente `ASSINADOR_JAR`
3. Pasta `~/.hubsaude/assinador.jar`
4. Pasta atual (`./assinador.jar`)

---

## Usando com token físico (PKCS#11)

Para assinar com um **token físico** (smart card, e-token) ou com o simulador **SoftHSM2**, passe o JSON de configuração no parâmetro `--config`:

```bash
./assinatura sign \
  --bundle     bundle.json \
  --provenance provenance.json \
  --config     '{"TOKEN":{"library":"/usr/lib/softhsm/libsofthsm2.so","slot":"0","pin":"1234","alias":"minha-chave"}}' \
  --cert       certificado.cer \
  --timestamp  1751328000 \
  --estrategia AD_RB \
  --pid        "https://politica.exemplo.gov.br|0.0.1"
```

| Campo em `--config` | Descrição |
|---|---|
| `library` | Caminho para a biblioteca PKCS#11 (`.so` no Linux, `.dll` no Windows) |
| `slot` | Número do slot do token |
| `pin` | PIN de autenticação do usuário |
| `alias` | Nome (label) da chave privada no token |

Quando `--config` é `{}` (modo padrão), a assinatura é gerada em **modo simulado**: a estrutura criptográfica está correta para integração, mas sem RSA real — adequado para desenvolvimento e testes.

---

## Diagnóstico com `--verbose`

A opção `--verbose` ativa o nível `DEBUG` do logging estruturado (`slog`). As mensagens são emitidas para `stderr` no formato:

```
time=2025-06-30T12:00:00.000Z level=DEBUG msg="assinador.jar encontrado" source=flag path=/home/user/assinador.jar
time=2025-06-30T12:00:00.001Z level=DEBUG msg="executando assinador" java=/usr/bin/java args="-jar /home/user/assinador.jar SIGN ..."
```

Sem `--verbose`, apenas mensagens de nível `INFO` e acima são exibidas.

---

## O que fazer se algo der errado

**"assinador.jar não encontrado"**
Coloque o arquivo `assinador.jar` na mesma pasta do executável, ou use a opção `--jar /caminho/para/assinador.jar`.

**"Java não encontrado"**
A ferramenta vai tentar baixar o Java 21 automaticamente. Se o download falhar (sem internet, por exemplo), instale o Java manualmente em [adoptium.net](https://adoptium.net/) e certifique-se de que o comando `java` está disponível no terminal.

**"Porta em uso por outro serviço"**
A ferramenta detecta quando a porta está ocupada por um serviço que não é o assinador (ex.: a porta responde com status diferente de `200`). Use `--port` para escolher outra porta.

**Mensagem de erro no resultado**
O resultado sempre vem em formato JSON. Leia o campo `"details"` — ele descreve o que deu errado. O campo `"diagnostics"` indica o código do erro específico.

---

## Exemplo completo (modo simulado)

O exemplo abaixo usa arquivos de teste e não exige certificado real:

```bash
# 1. Crie arquivos de teste
echo '{"resourceType":"Bundle"}' > bundle.json
echo '{"resourceType":"Provenance"}' > provenance.json
echo 'certificado-simulado' > cert.cer

# 2. Assine o documento
./assinatura sign \
  --bundle     bundle.json \
  --provenance provenance.json \
  --config     '{}' \
  --cert       cert.cer \
  --timestamp  1751328000 \
  --estrategia AD_RB \
  --pid        "https://exemplo.gov.br|0.0.1"

# 3. Copie o valor do campo "data" da resposta e valide
./assinatura validate \
  --jws    "COLE_O_VALOR_DO_CAMPO_DATA_AQUI" \
  --config '{"trustStore":[]}'
```

---

## Para desenvolvedores

### Compilar localmente

```bash
cd cli-assinatura
go build -o assinatura ./cmd/assinatura/main.go
```

### Executar os testes

```bash
go test ./... -v -coverprofile=coverage.out
go tool cover -html=coverage.out   # relatório visual de cobertura
```

Os testes incluem **cenários negativos** que verificam o comportamento da ferramenta em situações de falha: JAR ausente, porta ocupada por outro serviço (que responde com status diferente de `200`), servidor lento que extrapola o timeout, arquivo de estado corrompido, e `stop` sem servidor em execução.

### Lint

```bash
golangci-lint run
```

O lint é executado automaticamente no CI e bloqueia o build em caso de violações. A configuração está em `.golangci.yml`.
