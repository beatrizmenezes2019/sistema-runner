# ADR-003 — Gerenciamento de ciclo de vida via arquivo de estado em ~/.hubsaude/

**Data:** 2026-03-20  
**Status:** Aceito

## Contexto

O CLI precisa saber se o `assinador.jar` (ou o `simulador.jar`) já está rodando antes de iniciar uma nova instância. Alternativas consideradas:

1. **Verificar apenas se a porta está ocupada** (`net.Listen`)
2. **PID file em `/tmp/` ou diretório temporário**
3. **Arquivo de estado JSON em `~/.hubsaude/`**
4. **Socket Unix / named pipe**

## Decisão

Usar **arquivo de estado JSON em `~/.hubsaude/`** (`assinador.state.json`, `simulador.pid`), combinado com um **health check HTTP real** (`GET /health`).

## Justificativa

- **"Porta ocupada" não é suficiente:** Outro processo pode estar usando a mesma porta. O health check real confirma que é de fato o nosso servidor respondendo.
- **Diretório `~/.hubsaude/` é persistente entre sessões:** Permite que o CLI retome controle de um servidor iniciado em sessão anterior do terminal.
- **JSON legível por humanos:** Facilita diagnóstico manual (`cat ~/.hubsaude/assinador.state.json`).
- **Limpeza automática de estado obsoleto:** Se o PID registrado não responde ao health check, o arquivo é removido automaticamente.

## Consequências

- Em sistemas multi-usuário, cada usuário tem seu próprio `~/.hubsaude/`, isolando instâncias.
- Race condition teórica no start (dois processos verificam estado simultaneamente) é mitigada pelo health check, que confirma resposta real antes de registrar sucesso.
- O arquivo de estado não é um lock file; não usa `flock`. Em falha catastrófica do sistema, o arquivo pode ficar obsoleto — tratado como estado inativo na próxima execução.
