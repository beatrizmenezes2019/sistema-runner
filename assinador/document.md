# Assinador — Núcleo Criptográfico FHIR R4

Aplicação Java (Spring Boot 4 / JDK 21) responsável pela **assinatura digital** e **validação de assinaturas** de documentos de saúde no padrão FHIR R4, utilizando envelopes **JWS RS256 (JSON Web Signature)** compatíveis com ICP-Brasil.

O assinador é invocado como ferramenta de linha de comando (`java -jar assinador.jar`) ou via `cli-assinatura` (wrapper Go).

---

## Arquitetura Interna

```
AssinadorApplication (CommandLineRunner)
    └── SignatureParamsValidation   — valida argumentos antes de qualquer I/O
    └── SignatureService            — executa a criptografia e retorna OperationOutcome
```

**Fluxo geral:**
1. `AssinadorApplication.run()` recebe os args da linha de comando.
2. `SignatureParamsValidation` valida presença, formato e existência de cada parâmetro.
3. Se válido, `SignatureService` executa `generateSignature()` ou `validate()`.
4. O resultado é impresso em `stdout` como JSON FHIR R4 `OperationOutcome`.
5. Exit code `0` = sucesso, `1` = erro de negócio (severity `fatal`), `2` = parâmetros inválidos.

---

## Pré-requisitos

- Java 21 (JDK Temurin recomendado)
- Certificado digital em formato PKCS12 (`.p12`) com chave privada
- Certificado público exportado (`.cer` / `.der`) para o campo `x5c` do JWS

Para exportar o certificado público a partir do PKCS12:
```bash
keytool -export -alias SEU_ALIAS \
  -file certificado.cer \
  -keystore certificado.p12 \
  -storepass SUA_SENHA
```

---

## Operação SIGN

Lê o Bundle e Provenance FHIR, assina o conteúdo combinado com RS256 e retorna um `OperationOutcome` com o JWS em `diagnostics`.

### Sintaxe

```
java -jar assinador.jar SIGN \
  <bundle>       \
  <provenance>   \
  <config-cripto-json> \
  <cert>         \
  <timestamp>    \
  <estrategia>   \
  <pid>
```

### Parâmetros (posicionais, índices 1–7)

| # | Parâmetro | Tipo | Descrição |
|---|---|---|---|
| 1 | `bundle` | Caminho de arquivo | Bundle FHIR (`.json`) a ser assinado |
| 2 | `provenance` | Caminho de arquivo | Provenance FHIR (`.json`) complementar ao bundle |
| 3 | `config-cripto-json` | JSON string | Configuração do material criptográfico (ver abaixo) |
| 4 | `cert` | Caminho de arquivo | Certificado público (`.cer` / `.der`) para o cabeçalho `x5c` |
| 5 | `timestamp` | Long (Unix seconds) | Instante da assinatura — deve ser positivo e razoável |
| 6 | `estrategia` | String | Estratégia de carimbo de tempo (ex.: `AD_RB`, `AD_RT`) |
| 7 | `pid` | String | Identificador do assinante (PID / URL da política) |

### Formatos de `config-cripto-json`

**PKCS12 (arquivo ou Base64):**
```json
{
  "PKCS12": {
    "Conteúdo": "caminho/para/certificado.p12",
    "Senha": "sua-senha",
    "Alias": "seu-alias"
  }
}
```
O campo `Conteúdo` pode ser um **caminho de arquivo** (se contiver `/`, `\` ou `:`) ou uma string **Base64** do arquivo `.p12`.

**TOKEN / SMARTCARD (PKCS11 — em desenvolvimento):**
```json
{
  "TOKEN": {
    "PIN": "1234",
    "Identificador": "alias-do-token",
    "slotId": 0
  },
  "middlewareCrypto": {
    "Biblioteca": {
      "Caminho": "/usr/lib/libpkcs11.so"
    }
  }
}
```

### Exemplo de execução

```bash
java -jar assinador.jar SIGN \
  "C:\teste\bundle.json" \
  "C:\teste\provenance.json" \
  "{\"PKCS12\":{\"Conteúdo\":\"C:\\teste\\certificado.p12\",\"Senha\":\"senha123\",\"Alias\":\"assinador-teste\"}}" \
  "C:\teste\certificado.cer" \
  1751328001 \
  "AD_RB" \
  "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.0.2"
```

### Resposta de sucesso (SIGN)

```json
{
  "resourceType": "OperationOutcome",
  "id": "a1b2c",
  "text": { "status": "generated", "div": "..." },
  "issue": [{
    "severity": "information",
    "code": "informational",
    "details": { "text": "Assinatura gerada com sucesso" },
    "diagnostics": "eyJhbGciOiJSUzI1NiIsInR5cCI6..."
  }]
}
```

O campo `diagnostics` contém o **JWS compacto** no formato `header.payload.signature` (Base64Url), que deve ser usado como entrada para a operação `VALIDATE`.

---

## Operação VALIDATE

Verifica a integridade criptográfica da assinatura, a confiança do certificado e o status de revogação.

### Sintaxe

```
java -jar assinador.jar VALIDATE \
  <jws-ou-operation-outcome> \
  <config-json>
```

### Parâmetros (posicionais, índices 1–2)

| # | Parâmetro | Tipo | Descrição |
|---|---|---|---|
| 1 | `jws` | String | JWS compacto (`header.payload.signature`) **ou** JSON `OperationOutcome` com o JWS em `issue[0].diagnostics` |
| 2 | `config-json` | JSON string | Configuração de validação (ver abaixo) |

### Formato de `config-json`

```json
{
  "trustStore": ["sha256hex_do_cert_raiz"],
  "minCertIssueDate": 1751328000,
  "referenceTimestamp": 1751328001,
  "timeoutOcsp": 30,
  "timeoutCrl": 30,
  "revocationPolicy": "strict",
  "ocspUnknownHandling": "treat-as-revoked"
}
```

| Campo | Padrão | Descrição |
|---|---|---|
| `trustStore` | — | Lista de hashes SHA-256 (hex) dos certificados raiz confiáveis. **Obrigatório.** |
| `minCertIssueDate` | `1751328000` | Unix timestamp mínimo de emissão do certificado (segundos) |
| `referenceTimestamp` | agora | Timestamp de referência para validar vigência do certificado |
| `timeoutOcsp` | `30` | Timeout em segundos para consulta OCSP |
| `timeoutCrl` | `30` | Timeout em segundos para download de CRL |
| `revocationPolicy` | `"strict"` | `"strict"` = falha se não conseguir checar revogação; `"soft-fail"` = ignora erros de rede |
| `ocspUnknownHandling` | `"treat-as-revoked"` | O que fazer quando OCSP responde `UNKNOWN`: `"treat-as-revoked"` ou `"allow"` |

### Fluxo de validação

1. Parseia o JWS (compacto ou extraído do `OperationOutcome`).
2. Decodifica o cabeçalho protegido e extrai o campo `x5c` (cadeia de certificados).
3. Calcula SHA-256 do certificado raiz e verifica contra `trustStore`.
4. Verifica a assinatura RSA-SHA256 com a chave pública do certificado do assinante.
5. Consulta revogação: OCSP (se presente no AIA do cert) → CRL (CDPs do cert).
6. Retorna `OperationOutcome` com resultado.

### Exemplo de execução

```bash
java -jar assinador.jar VALIDATE \
  "eyJhbGciOiJSUzI1NiIsIng1YyI6WyIuLi4iXX0.cGF5bG9hZA.c2lnbmF0dXJl" \
  "{\"trustStore\":[\"f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2\"],\"revocationPolicy\":\"strict\"}"
```

### Resposta de sucesso (VALIDATE)

```json
{
  "resourceType": "OperationOutcome",
  "issue": [{
    "severity": "information",
    "code": "informational",
    "details": { "text": "Assinatura validada com sucesso" },
    "diagnostics": "SUCCESS"
  }]
}
```

### Respostas de erro comuns

| `diagnostics` | Causa |
|---|---|
| `CONFIG.TRUST-STORE-NOT-FOUND` | Hash SHA-256 do certificado raiz não está no `trustStore` |
| `CRYPTO.SIGNATURE-INVALID` | Assinatura RS256 não confere com o payload |
| `CERT.REVOKED` | Certificado revogado (OCSP ou CRL) |

---

## Formato de Resposta Padrão

Todas as saídas seguem o FHIR R4 `OperationOutcome`:

```json
{
  "resourceType": "OperationOutcome",
  "id": "<uuid-5-chars>",
  "text": { "status": "generated", "div": "..." },
  "issue": [{
    "severity": "information | fatal",
    "code": "informational | exception | security | structure",
    "details": { "text": "<descrição legível>" },
    "diagnostics": "<dado técnico ou JWS>",
    "location": ["<caminho do campo com erro, se houver>"]
  }]
}
```

---

## Validação de Parâmetros

Antes de qualquer operação criptográfica, `SignatureParamsValidation` verifica cada argumento e retorna mensagens de erro descritivas com dicas de correção. Exemplos:

```
[ERRO] Arquivo 'bundle (args[1])' não encontrado: 'C:\nao-existe.json'.
[DICA] Verifique se o caminho está correto e o arquivo existe.

[ERRO] Parâmetro 'timestamp' (args[5]) não é um número inteiro válido: 'abc'.
[DICA] Forneça um timestamp Unix em segundos (ex.: 1751328000).
```

---

## Testes

Os testes unitários ficam em `src/test/java/com/ufg/assinador/`.

```bash
# Rodar todos os testes
cd assinador
mvn test

# Rodar apenas os testes de validação de parâmetros
mvn test -Dtest=SignatureParamsValidationTest
```

**Cobertura atual:**
- `SignatureParamsValidationTest` — 15 casos cobrindo sucesso, argumentos insuficientes, arquivos inexistentes, JSON malformado, timestamp inválido e campos vazios para `SIGN` e `VALIDATE`.
- `AssinadorApplicationTests` — verifica carregamento do contexto Spring com mocks dos serviços.

---

## Limitações Conhecidas

- **PKCS11/TOKEN/SMARTCARD**: a estrutura de código existe, mas a comunicação com o hardware (SunPKCS11) não está integrada e testada.
- **OCSP**: o método `checkOCSP` retorna sempre `GOOD` (stub). A verificação real de revogação ocorre apenas via CRL.
- **REST API**: o assinador funciona exclusivamente via CLI. Endpoints HTTP ainda não foram implementados.
