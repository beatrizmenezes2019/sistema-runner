# Sistema Runner

> Repositório da disciplina de **Implementação e Integração de Software** — UFG.

O **Sistema Runner** é um conjunto de ferramentas que facilita a criação e validação de **assinaturas digitais de documentos de saúde** no padrão ICP-Brasil, sem que o usuário precise saber programar em Java ou entender os detalhes técnicos por trás do processo.

---

## Como funciona?

O sistema é dividido em três partes que trabalham juntas:

| Módulo | O que faz |
|---|---|
| **`assinador`** (Java) | O motor interno que realiza a assinatura e a validação — você não precisa interagir com ele diretamente |
| **`cli-assinatura`** (executável) | Ferramenta de linha de comando para **assinar e validar** documentos digitais |
| **`cli-simulador`** (executável) | Ferramenta de linha de comando para **iniciar e gerenciar** o servidor simulador do HubSaúde |

Basta baixar o executável certo para o seu sistema (Windows, Linux ou macOS) e rodar os comandos — sem instalar Java, sem configurar nada.

---

## Documentação

- [Como assinar e validar documentos digitais (cli-assinatura)](cli-assinatura/document.md)
- [Como usar o simulador do HubSaúde (cli-simulador)](cli-simulador/document.md)
- [Referência técnica do motor de assinatura (assinador)](assinador/document.md)

---

## Download

Os executáveis prontos para uso estão disponíveis na aba [**Releases**](../../releases) do repositório.

Cada release inclui:
- `cli-assinatura-*-linux-amd64` — CLI de assinatura para Linux
- `cli-assinatura-*-windows-amd64.exe` — CLI de assinatura para Windows
- `cli-assinatura-*-darwin-amd64` — CLI de assinatura para macOS
- `cli-simulador-*-linux-amd64` — CLI do simulador para Linux
- `cli-simulador-*-windows-amd64.exe` — CLI do simulador para Windows
- `cli-simulador-*-darwin-amd64` — CLI do simulador para macOS
- `assinador.jar` — motor de assinatura Java (necessário para a cli-assinatura funcionar)
- `SHA256SUMS.txt` — checksums para verificar a integridade dos arquivos

---

## Status do Projeto

### ✅ O que já está funcionando

**Motor de assinatura (`assinador.jar`)**
- Operação `SIGN`: lê os arquivos de documento (bundle + provenance), gera uma assinatura digital no formato JWS JSON Serialization conforme o padrão ICP-Brasil e retorna um recurso FHIR `Signature`.
- Operação `VALIDATE`: recebe uma assinatura, verifica sua estrutura e retorna `OperationOutcome` com resultado da validação.
- Modo simulado: a criação de assinatura não exige uma chave criptográfica real — útil para testes e desenvolvimento.
- Validação antecipada de parâmetros: mensagens de erro claras indicando o que está errado e como corrigir.
- Modo servidor HTTP: pode rodar como serviço REST com endpoints `/sign`, `/validate`, `/health` e `/shutdown`.
- Auto-shutdown por inatividade (configurável por variável de ambiente).
- Testes automatizados cobrindo validação de parâmetros e endpoints HTTP.

**CLI de assinatura (`cli-assinatura`)**
- Comando `sign`: assina um documento com todos os parâmetros necessários.
- Comando `validate`: valida uma assinatura existente.
- Comando `start`: inicia o `assinador.jar` em modo servidor (HTTP) em background.
- Comando `stop`: encerra o servidor.
- Comando `status`: verifica se o servidor está rodando e respondendo.
- Comando `version`: exibe a versão atual.
- **Instalação automática do Java 21**: se Java não estiver instalado na máquina, o CLI faz o download e configura automaticamente.
- Localização automática do `assinador.jar` (flag `--jar`, variável de ambiente, pasta `~/.hubsaude/`, pasta atual).
- Flag `--verbose` para diagnóstico detalhado.
- Testes automatizados de localização do JAR e do Java.

**CLI do simulador (`cli-simulador`)**
- Comando `start`: baixa automaticamente o JAR do simulador HubSaúde (se não existir), inicia o processo em background e aguarda o servidor estar pronto para receber requisições.
- Comando `stop`: encerra o simulador de forma controlada.
- Comando `status`: verifica o estado do simulador (pronto / inicializando / parado) com health check real.
- Comando `version`: exibe a versão atual.
- **Download automático do JAR** do simulador: não é necessário baixar o arquivo manualmente.
- **Instalação automática do Java 21**: igual ao `cli-assinatura`.
- Gerenciamento de PID em arquivo (`~/.hubsaude/simulador.pid`).
- Log do simulador salvo em `~/.hubsaude/simulador.log`.

**Pipeline CI/CD (GitHub Actions)**
- Testes automáticos a cada push/PR na branch `main`.
- Testes em Linux **e Windows** (portabilidade comprovada em CI).
- Build multiplataforma: Linux, Windows e macOS para ambas as CLIs.
- Build do `assinador.jar` com Maven.
- Publicação automática de Release ao criar uma tag `v*`, com binários e checksums SHA256.

---

### 🚧 O que ainda está sendo desenvolvido (Roadmap)

**Motor de assinatura**
- Assinatura criptográfica real com chave privada PKCS12 (atualmente simulada).
- Suporte completo a tokens e smartcards (PKCS11).
- Consulta de revogação de certificados via OCSP real.
- Ampliar cobertura de testes com certificados de teste reais.

**CLI de assinatura**
- Modo interativo para digitar senha do PKCS12 sem expô-la no histórico do terminal.

**CLI do simulador**
- Comando `logs`: exibir os logs do simulador em tempo real.
- Testes automatizados dos comandos start/stop/status.

**Geral**
- Diagrama arquitetural atualizado.
- Guia de instalação end-to-end com screenshots.

---

## Estrutura do Repositório

```
sistema-runner/
├── assinador/          # Motor de assinatura (Java 21 + Spring Boot)
├── cli-assinatura/     # CLI para assinar/validar documentos (Go)
├── cli-simulador/      # CLI para gerenciar o simulador HubSaúde (Go)
├── .github/
│   └── workflows/
│       └── pipeline.yml   # Pipeline CI/CD (GitHub Actions)
├── .gitattributes
├── .gitignore
├── LICENSE
└── README.md
```

---

## Desenvolvimento Local

Para compilar e testar localmente, você precisa de **Java 21** e **Go 1.22+** instalados.

```bash
# Compilar o motor de assinatura
cd assinador
mvn clean package

# Compilar a CLI de assinatura
cd cli-assinatura
go build -o assinatura ./cmd/assinatura/main.go

# Compilar a CLI do simulador
cd cli-simulador
go build -o simulador ./cmd/simulador/main.go
```

---

## Licença

[MIT](LICENSE)
