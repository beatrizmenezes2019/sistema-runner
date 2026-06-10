# CLI do Simulador HubSaúde

Esta ferramenta permite **iniciar, parar e verificar** o servidor simulador do HubSaúde diretamente pelo terminal, sem precisar baixar ou configurar nada manualmente.

> Funciona em **Windows**, **Linux** e **macOS**.

---

## O que é o simulador?

O simulador reproduz o comportamento do servidor HubSaúde em ambiente local, permitindo testar integrações sem acessar o ambiente de produção. É a ferramenta ideal para desenvolvimento e testes.

---

## Instalação

### 1. Baixe o executável

Acesse a aba [**Releases**](../../releases) do repositório e baixe o arquivo correto para o seu sistema:

| Sistema | Arquivo para baixar |
|---|---|
| Windows | `cli-simulador-*-windows-amd64.exe` |
| Linux | `cli-simulador-*-linux-amd64` |
| macOS | `cli-simulador-*-darwin-amd64` |

### 2. Nada mais é necessário!

- **O arquivo do simulador é baixado automaticamente** na primeira vez que você executar o comando `start`.
- **Java é instalado automaticamente** caso não esteja presente no seu computador.

---

## Como usar

Abra o terminal (Prompt de Comando no Windows, Terminal no Linux/macOS) na pasta onde salvou o executável.

---

### Iniciar o simulador (`start`)

Liga o servidor do simulador em background. O comando aguarda o servidor ficar completamente pronto antes de retornar.

```bash
# No Windows
.\simulador.exe start

# No Linux / macOS
./simulador start
```

**Com porta personalizada:**
```bash
.\simulador.exe start --port 9090
```

**O que acontece automaticamente:**
1. Verifica se o Java está instalado — se não estiver, baixa e configura o Java 21.
2. Verifica se o arquivo do simulador existe — se não existir, faz o download.
3. Verifica se o simulador já está rodando — se estiver, reaproveita a instância existente.
4. Inicia o servidor e aguarda até que esteja pronto para receber requisições.

**Exemplo de saída:**
```
[info] Simulador iniciado (PID 12345). Aguardando readiness na porta 8080...
[info] Simulador pronto e respondendo na porta 8080.
```

---

### Verificar o estado do simulador (`status`)

Mostra se o simulador está rodando e respondendo normalmente.

```bash
.\simulador.exe status
.\simulador.exe status --port 9090
```

**Possíveis resultados:**

```
STATUS: PRONTO
  PID   : 12345
  Porta : 8080
  Health: OK (http://localhost:8080/health)
```

```
STATUS: PROCESSO EM EXECUÇÃO, MAS NÃO RESPONDE
  PID   : 12345
  Porta : 8080
  Health: FALHOU
  Dica  : O simulador pode estar ainda inicializando. Aguarde ou execute 'simulador stop' e tente novamente.
```

```
STATUS: PARADO
  Nenhuma instância registrada em ~/.hubsaude/simulador.pid
```

---

### Parar o simulador (`stop`)

Encerra o servidor do simulador que está rodando em background.

```bash
.\simulador.exe stop
```

**Exemplo de saída:**
```
[info] Simulador (PID 12345) encerrado com sucesso.
```

---

### Ver a versão instalada (`version`)

```bash
.\simulador.exe version
# Exemplo de saída: simulador v1.2.0 (commit abc1234)
```

---

## Opções globais

| Opção | O que faz |
|---|---|
| `--verbose` | Exibe informações extras de diagnóstico — útil para entender o que está acontecendo em caso de erro |

---

## Arquivos gerados automaticamente

O simulador utiliza a pasta `~/.hubsaude/` para guardar seus arquivos:

| Arquivo | O que é |
|---|---|
| `~/.hubsaude/hubsaude-validador-api.jar` | O servidor do simulador (baixado automaticamente) |
| `~/.hubsaude/simulador.pid` | O número identificador do processo em execução |
| `~/.hubsaude/simulador.log` | O registro de saída do simulador |
| `~/.hubsaude/jdk/` | O Java instalado automaticamente (se necessário) |

> No Windows, `~` equivale à pasta do seu usuário, por exemplo: `C:\Users\seu-nome\.hubsaude\`

---

## O que fazer se algo der errado

**"Java não encontrado" / download falhou**
A ferramenta tenta instalar o Java automaticamente. Se o download falhar (ex.: sem internet), instale o Java 21 manualmente em [adoptium.net](https://adoptium.net/).

**O simulador não fica pronto / timeout**
Execute `simulador status` para ver o estado atual. Se necessário, rode `simulador stop` e tente `simulador start` novamente. Verifique também se a porta 8080 não está sendo usada por outro programa com `simulador start --port 9090`.

**"Nenhuma instância registrada"**
O simulador não está rodando. Use `simulador start` para iniciá-lo.

---

## Fluxo típico de uso

```bash
# 1. Inicie o simulador
./simulador start

# 2. Verifique se está pronto
./simulador status

# 3. Use o simulador para seus testes...
#    (o servidor responde em http://localhost:8080)

# 4. Ao terminar, pare o simulador
./simulador stop
```
