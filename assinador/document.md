# Assinador — Motor de Assinatura Digital

Componente Java responsável por realizar as operações de **criação** e **validação** de assinaturas digitais no padrão ICP-Brasil. Pode ser invocado pela linha de comando (modo CLI) ou como servidor HTTP (modo servidor).

> **Modo atual:** simulado. A estrutura criptográfica gerada segue o padrão ICP-Brasil (JWS JSON Serialization, FHIR Signature), mas sem assinatura RSA real com chave privada. Adequado para desenvolvimento, testes e integração. Para uso com dispositivo criptográfico real, veja a seção [PKCS#11](#pkcs11--dispositivo-criptográfico).

---

## Referências ICP-Brasil

- [Caso de uso: criar assinatura](https://fhir.saude.go.gov.br/r4/seguranca/caso-de-uso-criar-assinatura.html)
- [Caso de uso: validar assinatura](https://fhir.saude.go.gov.br/r4/seguranca/caso-de-uso-validar-assinatura.html)

---

## Modos de operação

### Modo CLI (padrão quando há argumentos)

Recebe parâmetros pela linha de comando, executa a operação e encerra.

```bash
java -jar assinador.jar SIGN <args...>
java -jar assinador.jar VALIDATE <args...>
```

### Modo servidor (padrão quando não há argumentos)

Sobe um servidor HTTP na porta configurada e aguarda requisições REST.

```bash
java -jar assinador.jar
java -jar assinador.jar --server.port=9090
```

---

## Operação SIGN

### Contrato de argumentos (modo CLI)

```
java -jar assinador.jar SIGN \
  <bundle>        \  # args[1]: caminho do arquivo bundle.json
  <provenance>    \  # args[2]: caminho do arquivo provenance.json
  <config-cripto> \  # args[3]: JSON de configuração (em modo simulado, use '{}')
  <certificado>   \  # args[4]: caminho do arquivo de certificado (.cer / .der)
  <timestamp>     \  # args[5]: Unix timestamp em segundos (long > 0)
  <estrategia>    \  # args[6]: estratégia de carimbo (ex.: AD_RB)
  <pid>              # args[7]: URI da política de assinatura
```

### Saída em caso de sucesso

Recurso FHIR `Signature` com:
- `type`: tipo de assinatura (urn:iso:astm:E1762-95:2013 / 1.2.840.10065.1.12.1.1)
- `when`: data/hora da assinatura
- `data`: bytes do JWS JSON Serialization (RFC 7515 §3.2)

```json
{
  "type": [{ "system": "urn:iso:astm:E1762-95:2013", "code": "1.2.840.10065.1.12.1.1" }],
  "when": "2025-06-30T12:00:00+00:00",
  "data": "<base64 do JWS JSON>"
}
```

### Estrutura do JWS JSON gerado (dentro de `data`)

```json
{
  "payload": "<sha256(bundle||provenance) em Base64Url>",
  "signatures": [{
    "protected": "<header em Base64Url>",
    "header": {
      "rRefs": {
        "certRefs": [{
          "certDigest": {
            "digestValue": "<sha256 do certificado>",
            "digestMethod": "http://www.w3.org/2001/04/xmlenc#sha256"
          }
        }]
      }
    },
    "signature": "<sha256(protected.payload) em Base64Url>"
  }]
}
```

Protected header decodificado:
```json
{
  "alg": "RS256",
  "x5c": ["<certificado em Base64>"],
  "iat": 1751328000,
  "sigPId": { "id": "<pid informado>" }
}
```

> **Nota sobre o campo `signature`:** em modo simulado, o valor é `SHA-256(protected.payload)` em Base64Url — estruturalmente correto mas não é uma assinatura RSA real. Para produção, o `Pkcs11Service` realiza `RSA-SHA256` com a chave privada do token.

### Saída em caso de erro

`OperationOutcome` FHIR R4 com `severity: fatal`.

```json
{
  "resourceType": "OperationOutcome",
  "issue": [{
    "severity": "fatal",
    "code": "exception",
    "details": { "text": "Erro na geração da assinatura" },
    "diagnostics": "<mensagem do erro>"
  }]
}
```

---

## Operação VALIDATE

### Contrato de argumentos (modo CLI)

```
java -jar assinador.jar VALIDATE \
  <jws>    \  # args[1]: base64(JWS JSON), JWS compacto ou OperationOutcome JSON com JWS em diagnostics
  <config>    # args[2]: JSON de configuração da validação
```

### Formatos aceitos para `<jws>`

- **JWS JSON Serialization em Base64** — formato preferencial (saída do SIGN)
- **JWS JSON Serialization puro** — JSON iniciando com `{`
- **JWS Compacto** — três partes separadas por `.` (ex.: `eyJ...eyJ...sig`)
- **OperationOutcome JSON** — extrai o JWS do campo `diagnostics`

### Saída em caso de sucesso

```json
{
  "resourceType": "OperationOutcome",
  "issue": [{
    "severity": "information",
    "code": "informational",
    "details": { "text": "Assinatura validada com sucesso" },
    "diagnostics": "VALIDATION.SUCCESS"
  }]
}
```

### Saída em caso de erro estrutural

```json
{
  "resourceType": "OperationOutcome",
  "issue": [{
    "severity": "fatal",
    "code": "structure",
    "details": { "text": "Estrutura JWS inválida" },
    "diagnostics": "<descrição do problema>",
    "location": ["Signature.data"]
  }]
}
```

---

## PKCS#11 — Dispositivo Criptográfico

O `Pkcs11Service` permite usar um **token físico** (smart card, e-token) ou o **simulador SoftHSM2** para realizar assinaturas RSA reais.

### Configuração do `config-cripto` para TOKEN

```json
{
  "TOKEN": {
    "library": "/usr/lib/softhsm/libsofthsm2.so",
    "slot": "0",
    "pin": "1234",
    "alias": "minha-chave"
  }
}
```

| Campo | Descrição |
|---|---|
| `library` | Caminho para a biblioteca PKCS#11 (`.so` no Linux, `.dll` no Windows) |
| `slot` | Número do slot do token |
| `pin` | PIN de autenticação do usuário |
| `alias` | Nome (label) da chave privada no token |

### Setup com SoftHSM2 (ambiente de teste)

```bash
# Instalar SoftHSM2
sudo apt-get install softhsm2          # Debian/Ubuntu
brew install softhsm                   # macOS

# Inicializar token
softhsm2-util --init-token --slot 0 --label "MeuToken" --pin 1234 --so-pin 0000

# Gerar par de chaves RSA-2048
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen --key-type RSA:2048 --label "minha-chave"
```

### Comportamento quando o dispositivo não está disponível

Se a biblioteca não for encontrada ou o PIN estiver errado, o serviço retorna `Pkcs11Exception` com mensagem explicativa — nunca silencia o erro.

---

## API REST (modo servidor)

### `GET /health`

Verifica se o servidor está pronto para receber requisições.

**Resposta:** `200 OK`
```json
{ "status": "UP", "service": "assinador" }
```

### `POST /sign`

Cria uma assinatura digital.

**Corpo da requisição:**
```json
{
  "bundle":      "/caminho/bundle.json",
  "provenance":  "/caminho/provenance.json",
  "configCripto": "{}",
  "cert":        "/caminho/certificado.cer",
  "timestamp":   "1751328000",
  "estrategia":  "AD_RB",
  "pid":         "https://politica.exemplo.gov.br|0.0.1"
}
```

**Resposta sucesso:** `200 OK` com FHIR `Signature`
**Resposta erro de negócio:** `422 Unprocessable Entity` com FHIR `OperationOutcome`
**Resposta parâmetros inválidos:** `400 Bad Request` com `OperationOutcome`

### `POST /validate`

Valida uma assinatura digital.

**Corpo da requisição:**
```json
{
  "jws":        "<conteúdo da assinatura>",
  "configJson": "{\"trustStore\":[]}"
}
```

**Resposta sucesso:** `200 OK` com FHIR `OperationOutcome` (`VALIDATION.SUCCESS`)
**Resposta inválido:** `422 Unprocessable Entity` com detalhes do erro

### `POST /shutdown`

Encerra o servidor de forma controlada.

**Resposta:** `200 OK`
```json
{ "status": "SHUTTING_DOWN" }
```

---

## Exit codes (modo CLI)

| Código | Significado |
|---|---|
| `0` | Operação concluída com sucesso |
| `1` | Erro de negócio (OperationOutcome com `fatal`) |
| `2` | Erro de parâmetros (argumentos inválidos ou ausentes) |

---

## Configuração (variáveis de ambiente)

| Variável | Padrão | Descrição |
|---|---|---|
| `SERVER_PORT` | `8080` | Porta do servidor HTTP |
| `ASSINADOR_TIMEOUT_MINUTOS` | desativado | Minutos de inatividade antes do auto-shutdown |
| `SOFTHSM2_LIB` | `/usr/lib/softhsm/libsofthsm2.so` | Caminho alternativo para a biblioteca SoftHSM2 nos testes |

---

## Executar os testes

```bash
cd assinador
mvn test                # executa todos os testes
mvn test jacoco:report  # executa + gera relatório de cobertura em target/site/jacoco/
```

Os testes cobrem:

- **`AssinadorApplicationTests`** — carregamento do contexto Spring
- **`SignatureControllerTest`** — todos os endpoints HTTP via MockMvc
- **`SignatureParamsValidationTest`** — todas as validações de parâmetros SIGN e VALIDATE
- **`Pkcs11ServiceTest`** — integração PKCS#11 com SoftHSM2 (executado em CI; requer `SOFTHSM2_AVAILABLE=true` localmente)

Para rodar os testes PKCS#11 localmente:

```bash
# Instalar e configurar SoftHSM2 (ver seção PKCS#11)
export SOFTHSM2_AVAILABLE=true
mvn test
```

---

## Build

```bash
cd assinador
mvn clean package
# Gera: target/assinador-<versão>.jar
```

O JAR final é autocontido (fat-jar) com `Main-Class` configurado — sem dependências externas.
