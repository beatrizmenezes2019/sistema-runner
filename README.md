# sistema-runner

Repositório da disciplina de **Implementação e Integração de Software** — UFG.

O sistema é composto por três módulos que trabalham em conjunto para realizar a **assinatura digital e validação de documentos FHIR R4** no padrão ICP-Brasil:

| Módulo | Tecnologia | Papel |
|---|---|---|
| `assinador` | Java 21 + Spring Boot 4 | Núcleo criptográfico — assina e valida via JWS |
| `cli-assinatura` | Go 1.26 | Wrapper CLI que invoca o `assinador.jar` |
| `cli-simulador` | Go 1.22 | CLI para iniciar o simulador do HubSaúde |

---

## Documentação dos Módulos

- [Assinador Java — operações SIGN e VALIDATE](assinador/document.md)
- [CLI Assinatura — guia de uso](cli-assinatura/document.md)
- [CLI Simulador — guia de uso](cli-simulador/document.md)

---

## Status do Projeto

### O que já está implementado

**Assinador (`assinador.jar`)**
- Operação `SIGN`: lê Bundle + Provenance FHIR, extrai chave privada de PKCS12, gera JWS compacto (RS256) e retorna `OperationOutcome` FHIR R4.
- Operação `VALIDATE`: aceita JWS compacto ou `OperationOutcome` JSON, verifica assinatura criptográfica (RS256), checa Trust Store via SHA-256 do certificado raiz, consulta revogação por OCSP e CRL.
- Suporte a material criptográfico: **PKCS12** (arquivo ou Base64) e estrutura para TOKEN/SMARTCARD (PKCS11 parcial).
- Validação antecipada de parâmetros (`SignatureParamsValidation`) com mensagens de erro e dicas de correção.
- Saída padronizada em FHIR R4 `OperationOutcome` em todos os cenários (sucesso e erro).
- **Testes unitários** cobrindo toda a lógica de validação de parâmetros (`SignatureParamsValidationTest`) e carregamento do contexto Spring (`AssinadorApplicationTests`).

**CLI Assinatura (`cli-assinatura`)**
- Comando `sign` com flags tipadas e obrigatórias validadas pelo Cobra: `--bundle`, `--provenance`, `--config`, `--cert`, `--timestamp`, `--estrategia`, `--pid`.
- Comando `validate` com flags `--jws` e `--config`.
- Comando `version` com versão e commit injetados via `ldflags` no build.
- Localização automática do `assinador.jar` em quatro fontes (flag `--jar`, variável de ambiente, `~/.hubsaude/`, diretório atual).
- Localização automática do `java` via `JAVA_HOME` ou `PATH`.
- Flag global `--verbose` para diagnóstico e `--jar` para caminho explícito.
- Testes unitários para `resolveJar` e `resolveJava`.

**CLI Simulador (`cli-simulador`)**
- Comando `start`: inicia o `simulador.jar` em background via `exec.Command` e exibe o PID do processo.
- Comando `version`.

**Pipeline CI/CD (GitHub Actions)**
- Testes automatizados Go (`cli-assinatura`) e Java (`assinador`) a cada push/PR na `main`.
- Build cross-platform (Linux, Windows, macOS/amd64) para ambas as CLIs.
- Build do `assinador.jar` com Maven.
- Publicação automática de GitHub Release em tags `v*`, incluindo binários, JAR e arquivo `SHA256SUMS.txt`.

---

### O que falta fazer (Roadmap)

**Assinador**
- Implementar PKCS11 completo (comunicação real com Tokens e Smartcards via SunPKCS11).
- Implementar endpoints REST (`spring-boot-starter-restclient`) para expor `SIGN` e `VALIDATE` como API HTTP, eliminando a dependência exclusiva da linha de comando.
- Implementar OCSP real (atualmente o stub retorna sempre `GOOD`).
- Ampliar cobertura de testes: testes de integração para `SignatureService` com certificados de teste.

**CLI Assinatura**
- Melhorar usabilidade: modo interativo para entrada da senha do PKCS12 sem expô-la no histórico do shell.
- Suporte ao modo servidor (chamar a API REST quando o assinador estiver rodando como serviço, sem necessidade do JAR local).

**CLI Simulador**
- Implementar comando `stop` para encerrar o processo iniciado pelo `start`.
- Implementar comando `status` para verificar se o simulador está rodando.
- Gerenciamento de PID (gravar e recuperar o PID do processo em arquivo).
- Implementar `logs` para acompanhar a saída do simulador em tempo real.

**Geral**
- Documentação de instalação end-to-end (pré-requisitos, download dos binários da Release, configuração do ambiente).
- Diagrama arquitetural do ecossistema completo.
