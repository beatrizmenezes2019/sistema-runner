# ADR-001 — Go como linguagem dos CLIs

**Data:** 2026-03-10  
**Status:** Aceito

## Contexto

O sistema precisava de dois executáveis de linha de comando (assinatura e simulador) que funcionassem em Windows, Linux e macOS sem exigir que o usuário final instale nenhum runtime. As alternativas consideradas foram Python, Node.js e Go.

## Decisão

Usar **Go 1.26** para ambos os CLIs.

## Justificativa

- **Binário único sem dependências:** Go compila para um executável estático por padrão. O usuário baixa um arquivo e executa — sem instalar Python, Node ou qualquer runtime.
- **Cross-compilation nativa:** `GOOS=windows GOARCH=amd64 go build` gera um `.exe` a partir de Linux sem ferramentas adicionais. Essencial para o pipeline de CI/CD multiplataforma.
- **Biblioteca padrão suficiente:** HTTP client, arquivos, processos, JSON, SHA-256 — tudo disponível sem dependências externas, reduzindo risco de supply chain.
- **Cobra CLI:** Framework maduro para parsing de comandos com suporte a `--help`, subcomandos e flags tipadas.

## Consequências

- Código de operações específicas de plataforma (como `syscall.SysProcAttr.Setsid`) exige build tags (`//go:build !windows`), adicionando um pouco de complexidade.
- A lógica de negócio (assinatura digital) permanece no `assinador.jar` em Java, separando as responsabilidades.
