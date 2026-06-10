# ADR-002 — Modo simulado sem criptografia RSA real

**Data:** 2026-03-15  
**Status:** Aceito

## Contexto

A especificação exige assinatura digital no padrão ICP-Brasil (JWS JSON Serialization, FHIR Signature). A implementação real requer um certificado emitido por uma AC credenciada ICP-Brasil, uma chave privada RSA protegida (PKCS#12 ou PKCS#11) e acesso a CRL/OCSP para validação de revogação — infraestrutura inviável em ambiente de desenvolvimento e testes.

## Decisão

Implementar o `assinador.jar` em **modo simulado**: a estrutura criptográfica gerada (JWS JSON Serialization, FHIR Signature, campos `alg`, `x5c`, `sigPId`, `rRefs`) segue fielmente o padrão ICP-Brasil, mas a assinatura em si é `SHA-256(protected.payload)` em vez de `RSA-SHA256(chave_privada, protected.payload)`.

## Justificativa

- **Foco no contrato de integração:** O objetivo do projeto é o CLI e o ciclo de vida do servidor, não a criptografia em si. A estrutura correta dos dados é suficiente para validar a integração.
- **Testabilidade:** Testes determinísticos e sem dependência de certificados reais.
- **Documentado explicitamente:** O modo simulado é documentado no `assinador/document.md` e no `README.md`, deixando claro que a estrutura está correta mas a assinatura RSA não é real.

## Consequências

- A saída do SIGN não pode ser usada em produção sem substituir `SignatureService` por uma implementação com chave real.
- A validação verifica apenas a estrutura do JWS, não a assinatura criptográfica.
- Suporte a PKCS#11 (SunPKCS11 + SoftHSM2) é integrado como caminho de upgrade para uso com dispositivo real.
