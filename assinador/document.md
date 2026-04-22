# Assinador e Validador FHIR R4

Este projeto é uma ferramenta de linha de comando (CLI) desenvolvida em Java para realizar a assinatura digital e a validação de documentos de saúde no padrão **FHIR R4**, utilizando envelopes **JWS (JSON Web Signature)**.

---

## 📋 1. Pré-requisitos e Configuração

Para executar as operações, você precisará dos seguintes arquivos em uma pasta local (ex: `C:\teste\arquivos\`):

1.  **bundle.json**: O recurso FHIR Bundle (conteúdo a ser assinado).
2.  **provenance.json**: O recurso FHIR Provenance (metadados da assinatura).
3.  **certificado.p12**: Certificado digital PKCS12 contendo a chave privada.
4.  **certificado.cer**: Certificado público exportado (necessário para o campo `x5c`).

### Como gerar o arquivo `certificado.cer`
O validador exige a parte pública do certificado para embuti-la no cabeçalho da assinatura. Gere-o através do terminal ou CMD:

```bash
keytool -export -alias SEU_ALIAS -file certificado.cer -keystore certificado.p12 -storepass SUA_SENHA
```

## 📋 2. Operação: SIGN (Geração de Assinatura)

A função SIGN lê os recursos FHIR, assina-os utilizando a chave privada e retorna um OperationOutcome contendo o JWS gerado.

### Comando de Execução

```bash
java -jar assinador.jar SIGN \
    "C:\path\to\bundle.json" \
    "C:\path\to\provenance.json" \
    "{\"PKCS12\":{\"Conteúdo\":\"C:\\path\\to\\certificado.p12\",\"Senha\":\"senha123\",\"Alias\":\"meu-alias\"}}" \
    "C:\path\to\certificado.cer" \
    1751328000 \
    "iat" \
    "https://sua-url-de-identificacao"
```

### Argumentos:

1. bundle.json: Caminho do Bundle.
2. provenance.json: Caminho do Provenance.
3. JSON_Config: Configuração da chave privada (PKCS12 ou Hardware).
4. certificado.cer: Caminho do certificado público.
5. Timestamp: Validade da assinatura (formato Epoch).
6. Estratégia: Tipo de carimbo de tempo (ex: iat).
8. PID: Identificador da política de assinatura.


## 📋 3. Operação: VALIDATE (Validação de Assinatura)

A função VALIDATE verifica a integridade matemática da assinatura, a validade do certificado e se a Raiz do certificado é confiável.

### Comando de Execução
```bash
java -jar assinador.jar VALIDATE \
    "CONTEUDO_JWS_OU_OPERATION_OUTCOME_BASE64" \
    "{\"trustStore\":[\"hash_sha256_da_raiz\"],\"revocationPolicy\":\"strict\"}"
```
### Argumentos:

1. JWS_Data: O conteúdo gerado na função SIGN (pode ser o JWS puro ou o JSON do OperationOutcome completo em base 64).
2. JSON_Config: Configuração da validação (Trust Store, timeouts, políticas).


## 📋 4. Como Executar os Testes no IntelliJ / CLI

### Testando a Geração (SIGN):

1. Configure os arquivos na pasta C:\teste\arquivos\.
2. No IntelliJ, vá em Run > Edit Configurations.
3. Em Program Arguments, cole os argumentos da seção 2.
4. Execute. O resultado será um JSON começando com {"resourceType": "OperationOutcome" ...}.

### Testando a Validação (VALIDATE):

1. Copie o valor de diagnostics gerado no teste anterior.
2. Altere os Program Arguments para: VALIDATE "COLE_O_JWS_AQUI" "{\"trustStore\":[\"hash_da_sua_raiz\"]}".
3. Verifique se o retorno é Assinatura validada com sucesso.

## 📋 5. Estrutura de Resposta (Padrão)
Todas as respostas seguem o formato FHIR OperationOutcome:

Sucesso: severity: information, code: informational.

Erro: severity: fatal, code: exception/security/structure.

Nota: O JWS gerado é um padrão compacto composto por três partes separadas por pontos: Header.Payload.Signature.

Exemplo de Resposta de Sucesso:
```JSON
{
    "resourceType": "OperationOutcome",
    "issue": [
        {
            "severity": "information",
            "code": "informational",
            "details": 
                { 
                    "text": "Assinatura validada com sucesso" 
                },
            "diagnostics": "SUCCESS"
        }
    ]
}
```

## 📋 6. Teste facilitado

1. Descompacte a pasta [teste.zip](https://drive.google.com/file/d/1kQ5SUSmutBYqf7jUD80e8jx6OOaTZRi1/view?usp=sharing) em C:\;
2. Para criar uma assinatura, acesse a pasta C:\teste no cmd e execute o comando:
```bash
java -jar assinador.jar "SIGN" "C:\\teste\\arquivos\\bundle.json" "C:\\teste\\arquivos\\provenance.json" "{\"PKCS12\":{\"Conteúdo\":\"C:\\\\teste\\\\arquivos\\\\certificado.p12\",\"Senha\":\"senha123\",\"Alias\":\"assinador-teste\"}}" "C:\\teste\\arquivos\\certificado.cer" 1751328000 "iat" "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.0.2"
```
3. Para validar uma assinatura, acesse a pasta C:\teste no cmd e execute o comando:
```bash
java -jar assinador.jar "VALIDATE" "ZXlKcFlYUWlPakUzTlRFek1qZ3dNREFzSW1Gc1p5STZJbEpUTWpVMklpd2ljMmxuVUVsa0lqb2lhSFIwY0hNNkx5OW1hR2x5TG5OaGRXUmxMbWR2TG1kdmRpNWljaTl5TkM5elpXZDFjbUZ1WTJFdlNXMXdiR1Z0Wlc1MFlYUnBiMjVIZFdsa1pTOWljaTVuYnk1elpYTXVjMlZuZFhKaGJtTmhmREF1TUM0eUlpd2llRFZqSWpwYklpSmRmUS5ldzBLSUNBaWNtVnpiM1Z5WTJWVWVYQmxJam9nSWtKMWJtUnNaU0lzRFFvZ0lDSjBlWEJsSWpvZ0ltTnZiR3hsWTNScGIyNGlMQTBLSUNBaVpXNTBjbmtpT2lCYlhRMEtmWHNOQ2lBZ0luSmxjMjkxY21ObFZIbHdaU0k2SUNKUWNtOTJaVzVoYm1ObElpd05DaUFnSW1GblpXNTBJam9nV3lCN0lDSjNhRzhpT2lCN0lDSmthWE53YkdGNUlqb2dJbE5wWjI1bGNpSWdmU0I5SUYwc0RRb2dJQ0owWVhKblpYUWlPaUJiWFEwS2ZRLm53M3RINnFaZTNsdWlHVE5RN0ZmRERmWEh1a0ZpQzluNno3LWYtaFpVdjU2VEl1VFpyR0hKaXRDRFBaS3BNQzRKM000OVpqeHk0cWlFdjBjZTUteU9NN243RHUtMFMtbnpCTlkxSjdBeEpCdW1ZSTczVHZQZTRwdWpRb24zUUNXTXhic2RkNEJEYUJVaDl5cUZlbTRpTTJZQVV4aFctY3JZR01vZDZKQ3BRcVFQQ0FQeXozZDNoOVI3TUpxYmlFMlBkc29MWGV1c2VpeHBRNFJoUFEtY1E0TW9ROWkzbzFtRERCZ3dHRE1WaUxBREdiUkZjcHVueWZBWWxBcmZNTkxURlRzU1UyU1hZbWNTNldfQXZ3MlV1SzR3eFBtNElQSmVWaWRERDBNNWJWUXVCUjdRN1JIdE1tUEpZbGdEdEZEZmRNTUR3UmVDX1RuR0xXU0MwbVpRZw==" "{\"trustStore\":[\"f2ca1bb6...\"],\"minCertIssueDate\":1751328000,\"referenceTimestamp\":1751328000,\"revocationPolicy\":\"strict\",\"ocspUnknownHandling\":\"treat-as-revoked\"}"
```
4. Garanta que esteja rodando os dois comandos acima utilizando a versão 21 do java;
