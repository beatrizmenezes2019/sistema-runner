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
- [Decisões arquiteturais (ADRs)](docs/adr/)

---

## Download

Os executáveis prontos para uso estão disponíveis na aba [**Releases**](../../releases) do repositório.

Cada release inclui:

| Arquivo | Descrição |
|---|---|
| `cli-assinatura-*-linux-amd64` | CLI de assinatura para Linux |
| `cli-assinatura-*-windows-amd64.exe` | CLI de assinatura para Windows |
| `cli-assinatura-*-darwin-amd64` | CLI de assinatura para macOS |
| `cli-simulador-*-linux-amd64` | CLI do simulador para Linux |
| `cli-simulador-*-windows-amd64.exe` | CLI do simulador para Windows |
| `cli-simulador-*-darwin-amd64` | CLI do simulador para macOS |
| `assinador.jar` | Motor de assinatura Java (necessário para o cli-assinatura) |
| `SHA256SUMS.txt` | Checksums SHA-256 para verificar a integridade dos arquivos |
| `*.sig` / `*.pem` | Assinaturas Cosign para verificação de autenticidade |

### Verificar integridade e autenticidade

```bash
# Verificar checksum SHA-256
sha256sum -c SHA256SUMS.txt

# Verificar assinatura Cosign (requer cosign instalado)
cosign verify-blob \
  --signature cli-assinatura-v1.0.0-linux-amd64.sig \
  --certificate cli-assinatura-v1.0.0-linux-amd64.pem \
  --certificate-identity-regexp "https://github.com/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  cli-assinatura-v1.0.0-linux-amd64
```

---

## Status do Projeto

### ✅ O que já está funcionando

**Motor de assinatura (`assinador.jar`)**
- Operação `SIGN`: gera assinatura digital no formato JWS JSON Serialization (ICP-Brasil) e retorna recurso FHIR `Signature`.
- Operação `VALIDATE`: verifica a estrutura da assinatura e retorna `OperationOutcome`.
- Modo simulado: estrutura criptográfica correta sem exigir chave privada real (adequado para desenvolvimento e testes).
- Suporte a PKCS#11 via `SunPKCS11`: integração com tokens físicos (smart cards, e-tokens) e simulador SoftHSM2.
- Validação antecipada de parâmetros com mensagens de erro claras (o quê, por quê e como resolver).
- Modo servidor HTTP com endpoints `/sign`, `/validate`, `/health` e `/shutdown`.
- Auto-shutdown por inatividade (configurável via `ASSINADOR_TIMEOUT_MINUTOS`).
- Testes automatizados: validação de parâmetros, endpoints HTTP, integração PKCS#11.
- Relatório de cobertura com JaCoCo publicado como artefato de CI.

**CLI de assinatura (`cli-assinatura`)**
- Comandos `sign`, `validate`, `start`, `stop`, `status`, `version`.
- Detecção de instância ativa via health check real (não apenas "porta ocupada").
- Instalação automática do Java 21 Temurin se não estiver disponível.
- Localização automática do `assinador.jar` (flag `--jar`, variável de ambiente, `~/.hubsaude/`, pasta atual).
- Logging estruturado via `slog`: nível INFO por padrão, DEBUG com `--verbose`.
- Testes de cenários negativos: JAR ausente, porta ocupada por outro serviço, servidor lento, estado corrompido.
- Lint obrigatório via `golangci-lint` no CI.
- Relatório de cobertura publicado como artefato de CI.

**CLI do simulador (`cli-simulador`)**
- Comandos `start`, `stop`, `status`, `version`.
- Download automático do JAR do simulador com verificação de integridade SHA-256.
- Instalação automática do Java 21 Temurin se necessário.
- Health check real antes de declarar o servidor pronto.
- Gerenciamento de PID em `~/.hubsaude/simulador.pid`.
- Log do simulador em `~/.hubsaude/simulador.log`.
- Logging estruturado via `slog`.

**Pipeline CI/CD (GitHub Actions)**
- Lint Go (`golangci-lint`) em Linux — bloqueia build se houver violação de estilo.
- Testes automáticos em Linux e Windows (portabilidade comprovada em CI).
- Testes Java com SoftHSM2 instalado (integração PKCS#11 validada em CI).
- Cobertura publicada como artefato: `go test -coverprofile` e JaCoCo.
- Build multiplataforma: Linux, Windows e macOS para ambas as CLIs.
- Publicação automática de Release ao criar tag `v*`, com checksums SHA-256 e assinaturas Cosign.

**Decisões Arquiteturais Documentadas (ADRs)**
- [ADR-001](docs/adr/ADR-001-go-para-clis.md): Go como linguagem dos CLIs
- [ADR-002](docs/adr/ADR-002-modo-simulado-sem-rsa-real.md): Modo simulado sem RSA real
- [ADR-003](docs/adr/ADR-003-gerenciamento-ciclo-de-vida-via-arquivo-estado.md): Estado em `~/.hubsaude/` + health check
- [ADR-004](docs/adr/ADR-004-porta-padrao-8080.md): Porta padrão 8080
- [ADR-005](docs/adr/ADR-005-provisionamento-jdk-temurin.md): Provisionamento de JDK via Adoptium Temurin

---

### 🚧 O que ainda pode ser evoluído

- Assinatura RSA real com chave privada PKCS#12 (atualmente o valor simulado é SHA-256, não RSA).
- Consulta de revogação de certificados via OCSP real.
- Modo interativo para digitar PIN do token sem expô-lo no histórico do terminal.
- Comando `simulador logs`: exibir os logs em tempo real.
- Guia de instalação end-to-end com screenshots.

---

## Estrutura do Repositório

```
sistema-runner/
├── assinador/                  # Motor de assinatura (Java 21 + Spring Boot)
├── cli-assinatura/             # CLI para assinar/validar documentos (Go)
│   └── .golangci.yml           # Configuração do lint
├── cli-simulador/              # CLI para gerenciar o simulador HubSaúde (Go)
│   └── .golangci.yml           # Configuração do lint
├── docs/
│   └── adr/                    # Architecture Decision Records
├── .github/
│   └── workflows/
│       └── pipeline.yml        # Pipeline CI/CD completo
├── .gitattributes
├── .gitignore
├── LICENSE
└── README.md
```

---

## Desenvolvimento Local

Para compilar e testar localmente, você precisa de **Java 21** e **Go 1.22+** instalados.

```bash
# Compilar e testar o motor de assinatura
cd assinador
mvn clean package       # compila e gera o JAR
mvn test                # executa os testes
mvn test jacoco:report  # executa testes + relatório de cobertura (target/site/jacoco/)

# Compilar a CLI de assinatura
cd cli-assinatura
go build -o assinatura ./cmd/assinatura/main.go
go test ./... -v -coverprofile=coverage.out

# Compilar a CLI do simulador
cd cli-simulador
go build -o simulador ./cmd/simulador/main.go
go test ./... -v -coverprofile=coverage.out

# Executar lint Go (requer golangci-lint instalado)
cd cli-assinatura && golangci-lint run
cd cli-simulador  && golangci-lint run
```

---

## Licença

[MIT](LICENSE)
