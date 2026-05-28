# CLI Assinatura

Wrapper de linha de comando desenvolvido em **Go 1.26** que encapsula o `assinador.jar`, eliminando a necessidade de construir manualmente os argumentos Java. O binário compilado é multiplataforma (Linux, Windows, macOS) e funciona sem instalação adicional.

---

## Instalação

Baixe o binário correspondente ao seu sistema na aba **Releases** do repositório ou compile localmente:

```bash
cd cli-assinatura
go build -o assinatura ./cmd/assinatura/main.go        # Linux/macOS
GOOS=windows go build -o assinatura.exe ./cmd/assinatura/main.go  # Windows (cross-compile)
```

Coloque o binário e o `assinador.jar` no mesmo diretório (ou configure uma das opções de localização abaixo).

---

## Localização do `assinador.jar`

O CLI procura o JAR nas seguintes fontes, **em ordem de prioridade**:

| Prioridade | Fonte | Como configurar |
|---|---|---|
| 1 | Flag `--jar` | `assinatura --jar /caminho/assinador.jar sign ...` |
| 2 | Variável de ambiente | `export ASSINADOR_JAR=/caminho/assinador.jar` |
| 3 | Pasta do usuário | `~/.hubsaude/assinador.jar` |
| 4 | Diretório atual | `./assinador.jar` |

Se nenhuma fonte for encontrada, o CLI exibe uma mensagem de erro com instruções.

---

## Localização do `java`

O CLI resolve o executável Java nas seguintes fontes:

| Prioridade | Fonte |
|---|---|
| 1 | `$JAVA_HOME/bin/java` (ou `java.exe` no Windows) |
| 2 | `java` no `PATH` do sistema |

---

## Flags Globais

Disponíveis em todos os comandos:

| Flag | Descrição |
|---|---|
| `--jar <caminho>` | Caminho explícito para o `assinador.jar` |
| `--local` | Força modo local (invoca o JAR diretamente, reservado para futura alternativa via REST) |
| `--verbose` | Exibe diagnóstico detalhado: caminho do JAR, do Java e comando completo executado |

---

## Comandos

### `sign` — Criar Assinatura Digital

Encaminha os parâmetros ao `assinador.jar SIGN` e imprime o `OperationOutcome` FHIR resultante.

**Sintaxe:**
```bash
assinatura sign \
  --bundle     <caminho> \
  --provenance <caminho> \
  --config     '<json>' \
  --cert       <caminho> \
  --timestamp  <unix-seconds> \
  --estrategia <string> \
  --pid        <string>
```

**Flags (todas obrigatórias):**

| Flag | Descrição |
|---|---|
| `--bundle` | Caminho para o arquivo Bundle FHIR (`.json`) |
| `--provenance` | Caminho para o arquivo Provenance FHIR (`.json`) |
| `--config` | JSON com material criptográfico PKCS12 ou TOKEN |
| `--cert` | Caminho para o certificado público (`.cer` / `.der`) |
| `--timestamp` | Timestamp Unix em segundos (ex.: `1751328001`) |
| `--estrategia` | Estratégia de assinatura: `AD_RB`, `AD_RT`, etc. |
| `--pid` | Identificador do assinante (PID ou URL da política) |

**Exemplos:**

```bash
# PKCS12 — arquivo .p12 local
assinatura sign \
  --bundle     bundle.json \
  --provenance provenance.json \
  --config     '{"PKCS12":{"Conteúdo":"certificado.p12","Senha":"senha123","Alias":"meu-alias"}}' \
  --cert       certificado.cer \
  --timestamp  1751328001 \
  --estrategia AD_RB \
  --pid        "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.0.2"

# PKCS12 — certificado em Base64 inline
assinatura sign \
  --bundle     bundle.json \
  --provenance provenance.json \
  --config     '{"PKCS12":{"Conteúdo":"MIIKXgIBAzCCCh...base64...","Senha":"senha123","Alias":"meu-alias"}}' \
  --cert       certificado.cer \
  --timestamp  1751328001 \
  --estrategia AD_RT \
  --pid        12345678901

# TOKEN de hardware (PKCS11)
assinatura sign \
  --bundle     bundle.json \
  --provenance provenance.json \
  --config     '{"TOKEN":{"PIN":"1234","Identificador":"alias","slotId":0},"middlewareCrypto":{"Biblioteca":{"Caminho":"/usr/lib/libpkcs11.so"}}}' \
  --cert       certificado.cer \
  --timestamp  1751328001 \
  --estrategia AD_RT \
  --pid        12345678901

# Com --verbose para diagnóstico
assinatura --verbose sign --bundle bundle.json ...
```

A saída é o JSON `OperationOutcome` do assinador impresso diretamente no `stdout`. Redirecione para um arquivo se necessário:
```bash
assinatura sign ... > resultado-sign.json
```

---

### `validate` — Validar Assinatura

Encaminha os parâmetros ao `assinador.jar VALIDATE`.

**Sintaxe:**
```bash
assinatura validate \
  --jws    '<jws-ou-json>' \
  --config '<json>'
```

**Flags (todas obrigatórias):**

| Flag | Descrição |
|---|---|
| `--jws` | JWS compacto (`header.payload.signature`) **ou** JSON `OperationOutcome` com o JWS em `issue[0].diagnostics` |
| `--config` | JSON de configuração com `trustStore` e políticas de revogação |

**Exemplos:**

```bash
# JWS compacto diretamente
assinatura validate \
  --jws    "eyJhbGciOiJSUzI1NiIsIng1YyI6WyIuLi4iXX0.cGF5bG9hZA.c2lnbmF0dXJl" \
  --config '{"trustStore":["f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"]}'

# Passando o OperationOutcome gerado pelo sign
assinatura validate \
  --jws    "$(cat resultado-sign.json)" \
  --config '{"trustStore":["f2ca1bb6..."],"revocationPolicy":"strict","ocspUnknownHandling":"treat-as-revoked"}'

# Com politica soft-fail (não falha se OCSP/CRL não responder)
assinatura validate \
  --jws    "eyJ..." \
  --config '{"trustStore":["abc123"],"revocationPolicy":"soft-fail"}'
```

---

### `version` — Versão do CLI

Exibe a versão semântica e o commit Git injetados no momento do build.

```bash
assinatura version
# Saída: assinatura v1.2.0 (commit a3f9c12)
```

Em builds locais sem ldflags, a saída será:
```
assinatura dev (commit unknown)
```

---

## Exit Codes

| Código | Significado |
|---|---|
| `0` | Operação concluída com sucesso |
| `1` | Erro de negócio (assinador retornou `severity: fatal`) ou erro ao localizar JAR/Java |
| `2` | Parâmetros inválidos rejeitados pelo assinador |

---

## Estrutura do Projeto

```
cli-assinatura/
├── cmd/
│   └── assinatura/
│       └── main.go          # ponto de entrada
├── internal/
│   └── cli/
│       ├── root.go          # comando raiz + flags globais (--jar, --local, --verbose)
│       ├── runner.go        # resolveJar(), resolveJava(), runJar()
│       ├── runner_test.go   # testes unitários de resolveJar e resolveJava
│       ├── sign.go          # comando sign e suas flags
│       ├── validate.go      # comando validate e suas flags
│       └── version.go       # comando version (BuildVersion, BuildCommit via ldflags)
├── go.mod
└── go.sum
```

---

## Testes

```bash
cd cli-assinatura
go test ./... -v
```

**Cobertura atual (`runner_test.go`):**

| Teste | O que verifica |
|---|---|
| `TestResolveJar_EnvVar` | JAR localizado via `ASSINADOR_JAR` |
| `TestResolveJar_Flag` | JAR localizado via flag `--jar` (`jarPath`) |
| `TestResolveJar_CurrentDir` | JAR localizado no diretório de trabalho atual |
| `TestResolveJar_NotFound` | Erro retornado quando nenhuma fonte encontra o JAR |
| `TestResolveJava_JavaHome` | Java localizado via `JAVA_HOME` |

---

## Build Multiplataforma

```bash
cd cli-assinatura

# Linux
GOOS=linux  GOARCH=amd64 go build -o build/assinatura-linux   ./cmd/assinatura/main.go

# Windows
GOOS=windows GOARCH=amd64 go build -o build/assinatura.exe    ./cmd/assinatura/main.go

# macOS
GOOS=darwin GOARCH=amd64 go build -o build/assinatura-macos   ./cmd/assinatura/main.go

# Com versão injetada
VERSION=v1.0.0
COMMIT=$(git rev-parse --short HEAD)
LDFLAGS="-X github.com/beatrizmenezes2019/sistema-runner/cli-assinatura/internal/cli.BuildVersion=${VERSION} \
         -X github.com/beatrizmenezes2019/sistema-runner/cli-assinatura/internal/cli.BuildCommit=${COMMIT}"
go build -ldflags "${LDFLAGS}" -o build/assinatura ./cmd/assinatura/main.go
```
