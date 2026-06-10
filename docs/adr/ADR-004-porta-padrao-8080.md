# ADR-004 — Porta padrão 8080

**Data:** 2026-03-20  
**Status:** Aceito

## Contexto

O `assinador.jar` e o `simulador.jar` precisam de uma porta HTTP padrão. Candidatos: 80, 443, 3000, 8080, 8443, 9090.

## Decisão

Usar **porta 8080** como padrão para ambos os servidores.

## Justificativa

- **Convencional para servidores HTTP de desenvolvimento:** 8080 é amplamente reconhecida como porta alternativa ao 80 para aplicações Java/Spring.
- **Não exige privilégios:** Portas abaixo de 1024 exigem root em Linux. 8080 funciona sem elevação de privilégio.
- **Configurável:** A porta padrão pode ser sobrescrita via `--port`, variável de ambiente `SERVER_PORT`, ou propriedade Spring `--server.port`.

## Consequências

- Se a porta 8080 estiver ocupada, o CLI falha com mensagem clara informando como usar `--port` para escolher outra.
- O simulador e o assinador usam a mesma porta padrão, mas nunca rodam simultaneamente na mesma porta — o usuário precisa especificar `--port` para um deles se quiser ambos ativos.
