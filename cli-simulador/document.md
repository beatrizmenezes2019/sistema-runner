# CLI Simulador

Ferramenta de linha de comando desenvolvida em **Go 1.22** para gerenciar o ciclo de vida do simulador do HubSaúde. O binário compilado é multiplataforma (Linux, Windows, macOS) e funciona sem instalação adicional.

> **Estado atual:** implementação inicial. Os comandos `start` e `version` estão disponíveis. A gestão completa do ciclo de vida (stop, status, logs) está no roadmap.

---

## Instalação

Baixe o binário correspondente ao seu sistema na aba **Releases** do repositório ou compile localmente:

```bash
cd cli-simulador
go build -o simulador ./cmd/simulador/main.go          # Linux/macOS
GOOS=windows go build -o simulador.exe ./cmd/simulador/main.go  # Windows (cross-compile)
```

Coloque o binário e o `simulador.jar` no mesmo diretório de trabalho.

---

## Pré-requisito

O simulador requer Java instalado e o arquivo `simulador.jar` presente no **diretório de trabalho atual** ao executar o comando `start`.

---

## Comandos

### `start` — Iniciar o Simulador

Inicia o `simulador.jar` como um processo filho em background e exibe o PID atribuído pelo sistema operacional.

**Sintaxe:**
```bash
simulador start
```

**Comportamento:**
- Executa `java -jar simulador.jar` em modo não-bloqueante (`cmd.Start()`).
- O processo do simulador continua rodando após o CLI retornar.
- Exibe o PID do processo iniciado para que possa ser encerrado manualmente se necessário.

**Exemplo de saída:**
```
Simulador iniciado com sucesso! PID: 12345
Use 'simulador stop' para encerrar.
```

**Atenção:** O comando `stop` ainda não está implementado. Para encerrar o simulador manualmente, use o PID exibido:

```bash
# Linux / macOS
kill 12345

# Windows
taskkill /PID 12345 /F
```

---

### `version` — Versão do CLI

Exibe a versão atual do CLI do simulador.

```bash
simulador version
# Saída: Sistema Runner CLI Simulador - Versão: 0.1.0
```

---

## Exit Codes

| Código | Significado |
|---|---|
| `0` | Comando executado com sucesso |
| `1` | Erro fatal (ex.: `simulador.jar` não encontrado ou sem permissão de execução) |

---

## Estrutura do Projeto

```
cli-simulador/
├── cmd/
│   └── simulador/
│       └── main.go          # ponto de entrada
├── internal/
│   └── cli/
│       ├── root.go          # comando raiz
│       ├── start.go         # comando start
│       └── version.go       # comando version
├── go.mod
└── go.sum
```

---

## Build Multiplataforma

```bash
cd cli-simulador

# Linux
GOOS=linux   GOARCH=amd64 go build -o build/simulador-linux   ./cmd/simulador/main.go

# Windows
GOOS=windows GOARCH=amd64 go build -o build/simulador.exe     ./cmd/simulador/main.go

# macOS
GOOS=darwin  GOARCH=amd64 go build -o build/simulador-macos   ./cmd/simulador/main.go
```

---

## Roadmap

As funcionalidades abaixo estão planejadas para sprints futuras:

| Funcionalidade | Descrição |
|---|---|
| `simulador stop` | Encerra o processo do simulador pelo PID salvo em arquivo |
| `simulador status` | Verifica se o simulador está em execução |
| `simulador logs` | Exibe a saída do simulador em tempo real (`tail -f`) |
| Gerenciamento de PID | Gravar o PID em `~/.hubsaude/simulador.pid` para uso pelos outros comandos |
| Localização do JAR | Mesma lógica do `cli-assinatura`: flag `--jar`, variável de ambiente `SIMULADOR_JAR`, `~/.hubsaude/simulador.jar`, diretório atual |
| Testes unitários | Cobertura dos comandos `start` e `stop` com processos mock |
