# sistema-runner
Repositório dedicado ao desenvolvimento do sistema Runner da disciplina de Implementação e Integração de Software.

# Documentação do sistema assinador (java)
[Processo de criação e validação das assinaturas](assinador/document.md)

# Documentação do sistema cli-assinatura (Go)
[Processo de criação e validação das assinaturas via CLI](cli-assinatura/document.md)

## 📊 Status do Projeto

Este projeto está em desenvolvimento ativo como parte da disciplina de Implementação e Integração de Software. Abaixo, detalhamos o progresso atual das entregas.

### ✅ O que já está pronto
* **Assinador Core (`assinador.jar`):** * Lógica de assinatura digital seguindo os padrões do ICP-Brasil (exceto PKCS11).
    * Validação de assinaturas e verificação de confiança via Trust Store.
    * Saída padronizada em FHIR OperationOutcome.
* **Infraestrutura de CI/CD (Pipeline):**
    * Build automatizado multiplataforma (Windows, Linux, macOS) para as CLIs em Go.
    * Build automatizado da aplicação Java (Maven).
    * Fluxo de publicação automática de Releases com versionamento por Tags.
* **Implementação parcial do CLI de assinatura:**
    * Realizada a chamada da aplicação assinador.jar através do cli-assinatura;
    * Build automatizado dos CLIs.
    * Fluxo de publicação automática de Releases com versionamento por Tags.
* **Documentação Técnica:**
    * Guia de uso e parâmetros das funções `SIGN` e `VALIDATE` do `assinador.jar`.
    * Guia de uso do CLI assinatura.

### 🛠️ O que falta fazer (Roadmap)
* **Lógica das CLIs (Go):**
    * Melhorar a usabilidade do wrapper que executa o `assinador.jar` via CLI, principalmente relacionado a captação dos parâmetros.
    * Implementar a gestão do ciclo de vida da aplicação de simulação.
* **Chamada REST do assinador.jar:**
    * Necessário criar os endpoints de acesso ao assinador.jar para criar e validar as assinaturas. 
* **Integração PKCS11:**
    * Finalizar a lógica de comunicação com hardwares (Tokens/Smartcards) no Assinador.
* **Qualidade e Testes:**
    * Implementação de testes unitários para o core do assinador.
    * Criação de testes automatizados para a pipeline de validação.
* **Documentação Geral:**
    * Manual de instalação do ecossistema completo e visão arquitetural do projeto.
