# ADR-005 — Provisionamento automático de JDK via Adoptium Temurin

**Data:** 2026-03-25  
**Status:** Aceito

## Contexto

O `assinador.jar` requer Java 21. O usuário do CLI pode não ter Java instalado. Alternativas para resolver isso:

1. **Exigir que o usuário instale Java manualmente** — quebra a experiência "baixar e usar".
2. **Embutir a JVM no binário do CLI** — inviável; uma JVM tem ~200MB.
3. **Baixar JDK automaticamente na primeira execução** — transparente para o usuário.
4. **Usar Docker** — requer Docker instalado, adiciona overhead.

## Decisão

Ao invocar o `assinador.jar`, o CLI verifica a disponibilidade do Java na seguinte ordem de prioridade:

1. `JAVA_HOME` env → `$JAVA_HOME/bin/java`
2. `java` no `PATH` do sistema
3. Cache local em `~/.hubsaude/jdk/bin/java`
4. **Download automático** do Adoptium Temurin JDK 21 via API pública (`api.adoptium.net/v3/binary/latest/21/ga/{os}/{arch}/jdk/hotspot/normal/eclipse`)

## Justificativa

- **Adoptium Temurin** é a distribuição OpenJDK gratuita, open source e sem restrições de licença de produção. Mantida pela Eclipse Foundation.
- **API estável:** `api.adoptium.net` oferece endpoint versionado para download por OS e arquitetura.
- **Cache local:** O JDK baixado é reutilizado em chamadas subsequentes, sem download repetido.
- **Respeitoso com o ambiente do usuário:** Se o usuário já tem Java configurado (JAVA_HOME ou PATH), ele é usado sem nenhum download.

## Consequências

- Primeira execução sem Java pode ser lenta (~200MB de download). O CLI informa o usuário com `[info] Java não encontrado. Baixando JDK 21 (Temurin)...`.
- O download requer conexão com a internet na primeira vez.
- Em ambientes corporativos com proxy, o usuário pode precisar configurar `HTTPS_PROXY`.
- A versão do JDK baixada é sempre a última GA do Java 21 no momento do download, não uma versão fixada. Isso pode mudar o comportamento entre downloads em versões de patch futuras — aceitável para modo de desenvolvimento/simulação.
