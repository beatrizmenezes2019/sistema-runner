package com.ufg.assinador.services;

import ca.uhn.fhir.context.FhirContext;
import org.hl7.fhir.r4.model.OperationOutcome;
import org.hl7.fhir.r4.model.Signature;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Serviço de assinatura digital (modo simulado ICP-Brasil).
 *
 * <p>Implementa as operações SIGN e VALIDATE conforme o modelo ICP-Brasil,
 * porém em modo <em>simulado</em>: a criptografia real (PKCS12, PKCS11, X.509,
 * CRL/OCSP) é omitida e substituída por valores placeholders estruturalmente
 * corretos.</p>
 *
 * <p>Referências ICP-Brasil:</p>
 * <ul>
 *   <li>Criar assinatura: https://fhir.saude.go.gov.br/r4/seguranca/caso-de-uso-criar-assinatura.html</li>
 *   <li>Validar assinatura: https://fhir.saude.go.gov.br/r4/seguranca/caso-de-uso-validar-assinatura.html</li>
 * </ul>
 */
@Service
public class SignatureService {

    private final FhirContext fhirContext = FhirContext.forR4();

    // -------------------------------------------------------------------------
    // SIGN
    // -------------------------------------------------------------------------

    /**
     * Gera uma assinatura digital simulada no formato ICP-Brasil.
     *
     * <p>Contrato de argumentos (índices 0..7):</p>
     * <pre>
     *   0: "SIGN"
     *   1: caminho bundle JSON (arquivo — existência validada)
     *   2: caminho provenance JSON (arquivo — existência validada)
     *   3: JSON de material criptográfico (presença e formato validados)
     *   4: caminho certificado (arquivo — existência validada)
     *   5: timestamp Unix (long)
     *   6: estratégia de assinatura (ex.: AD_RB)
     *   7: PID do assinante (policy ID URI)
     * </pre>
     *
     * <p>Saída em caso de sucesso: recurso FHIR {@code Signature} com
     * {@code Signature.data} = base64(JWS JSON Serialization).</p>
     * <p>Saída em caso de erro: recurso FHIR {@code OperationOutcome} com severity {@code fatal}.</p>
     */
    public String generateSignature(String[] args) {
        try {
            long timestamp = Long.parseLong(args[5].trim());

            // Leitura dos arquivos (existência já validada por SignatureParamsValidation)
            byte[] bundleBytes    = Files.readAllBytes(Paths.get(args[1]));
            byte[] provenanceBytes = Files.readAllBytes(Paths.get(args[2]));
            byte[] certBytes      = Files.readAllBytes(Paths.get(args[4]));

            String policyId  = args[7];   // ex.: urn:oid:2.16.76.1.7.1.1.1
            // args[6] (estratégia) é registrado mas não altera a estrutura simulada

            // Payload = SHA-256(bundle || provenance) em Base64Url
            byte[] combined = concatenate(bundleBytes, provenanceBytes);
            String payloadB64Url = sha256Base64Url(combined);

            // Protected header (JWS JSON Serialization)
            JSONObject protectedHeader = new JSONObject();
            protectedHeader.put("alg", "RS256");
            // x5c: array com o certificado em Base64 padrão (simulado: usa bytes do arquivo)
            protectedHeader.put("x5c", new JSONArray().put(Base64.getEncoder().encodeToString(certBytes)));
            protectedHeader.put("iat", timestamp);
            protectedHeader.put("sigPId", new JSONObject().put("id", policyId));

            String protectedB64Url = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(protectedHeader.toString().getBytes(StandardCharsets.UTF_8));

            // Signature = SHA-256(protectedB64Url + "." + payloadB64Url) em Base64Url
            // (valor simulado — não é uma assinatura RSA real)
            String sigInput = protectedB64Url + "." + payloadB64Url;
            String signatureB64Url = sha256Base64Url(sigInput.getBytes(StandardCharsets.UTF_8));

            // rRefs (LTV evidence) — estrutura mínima simulada
            JSONObject rRefs = new JSONObject();
            rRefs.put("certRefs", new JSONArray()
                    .put(new JSONObject().put("certDigest",
                            new JSONObject().put("digestValue", sha256Hex(certBytes))
                                           .put("digestMethod", "http://www.w3.org/2001/04/xmlenc#sha256"))));

            // JWS JSON Serialization (RFC 7515 §3.2)
            JSONObject jwsJson = new JSONObject();
            jwsJson.put("payload", payloadB64Url);
            JSONObject sigEntry = new JSONObject();
            sigEntry.put("protected", protectedB64Url);
            sigEntry.put("header", new JSONObject().put("rRefs", rRefs));
            sigEntry.put("signature", signatureB64Url);
            jwsJson.put("signatures", new JSONArray().put(sigEntry));

            // Serializa como FHIR Signature
            return serializeSignatureResource(jwsJson.toString(), timestamp);

        } catch (Exception e) {
            return buildOperationOutcome("fatal", "exception",
                    "Erro na geração da assinatura", e.getMessage(), null);
        }
    }

    // -------------------------------------------------------------------------
    // VALIDATE
    // -------------------------------------------------------------------------

    /**
     * Valida a estrutura de uma assinatura digital (modo simulado).
     *
     * <p>Contrato de argumentos (índices 0..2):</p>
     * <pre>
     *   0: "VALIDATE"
     *   1: base64(JWS JSON Serialization) ou JWS compacto
     *   2: JSON de configuração (trustStore, etc.)
     * </pre>
     *
     * <p>Em modo simulado, somente a estrutura do JWS é verificada
     * (campos obrigatórios presentes). A verificação criptográfica real
     * e a consulta CRL/OCSP são omitidas.</p>
     */
    public String validate(String[] args) {
        try {
            String rawInput = args[1].trim().replaceAll("\\s", "");

            String jwsRaw = decodeInput(rawInput);
            validateJwsStructure(jwsRaw);

            return buildOperationOutcome(
                    "information",
                    "informational",
                    "Assinatura validada com sucesso",
                    "VALIDATION.SUCCESS",
                    null
            );

        } catch (StructureException e) {
            return buildOperationOutcome("fatal", "structure",
                    "Estrutura JWS inválida", e.getMessage(), "Signature.data");
        } catch (Exception e) {
            return buildOperationOutcome("fatal", "exception",
                    "Erro interno na validação", e.getMessage(), null);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers — decodificação e validação estrutural
    // -------------------------------------------------------------------------

    /**
     * Decodifica o input: aceita base64(JSON), JSON puro, ou JWS compacto.
     */
    private String decodeInput(String raw) throws StructureException {
        // Caso 1: JWS compacto (header.payload.sig)
        if (!raw.startsWith("{") && raw.contains(".")) {
            return raw; // tratado no step seguinte como compacto
        }

        // Caso 2: JSON direto
        if (raw.startsWith("{")) {
            // Pode ser OperationOutcome com JWS em diagnostics
            try {
                JSONObject json = new JSONObject(raw);
                if (json.has("issue")) {
                    return json.getJSONArray("issue")
                               .getJSONObject(0)
                               .getString("diagnostics");
                }
            } catch (Exception ignored) { /* tratar como JWS JSON */ }
            return raw;
        }

        // Caso 3: base64 padrão de um JSON (Signature.data)
        try {
            byte[] decoded = Base64.getDecoder().decode(raw);
            String decoded64 = new String(decoded, StandardCharsets.UTF_8).trim();
            if (decoded64.startsWith("{")) {
                return decoded64;
            }
        } catch (IllegalArgumentException ignored) { /* não é base64 válido */ }

        throw new StructureException(
            "Input não reconhecido: deve ser base64(JWS JSON), JSON JWS, JWS compacto ou OperationOutcome JSON.");
    }

    /**
     * Valida a estrutura do JWS (compacto ou JSON Serialization).
     */
    private void validateJwsStructure(String jws) throws StructureException {
        if (jws.startsWith("{")) {
            // JWS JSON Serialization
            JSONObject obj;
            try {
                obj = new JSONObject(jws);
            } catch (Exception e) {
                throw new StructureException("JSON inválido: " + e.getMessage());
            }

            if (!obj.has("payload")) {
                throw new StructureException("Campo 'payload' ausente no JWS JSON.");
            }
            if (!obj.has("signatures") || obj.getJSONArray("signatures").isEmpty()) {
                throw new StructureException("Campo 'signatures' ausente ou vazio no JWS JSON.");
            }

            JSONObject sig = obj.getJSONArray("signatures").getJSONObject(0);
            if (!sig.has("protected")) {
                throw new StructureException("Campo 'protected' ausente em signatures[0].");
            }
            if (!sig.has("signature")) {
                throw new StructureException("Campo 'signature' ausente em signatures[0].");
            }

            // Decodificar e verificar o protected header
            try {
                byte[] protBytes = Base64.getUrlDecoder().decode(sig.getString("protected"));
                JSONObject ph = new JSONObject(new String(protBytes, StandardCharsets.UTF_8));
                if (!ph.has("alg")) {
                    throw new StructureException("Campo 'alg' ausente no protected header.");
                }
            } catch (StructureException se) {
                throw se;
            } catch (Exception e) {
                throw new StructureException("Não foi possível decodificar o protected header: " + e.getMessage());
            }

        } else if (jws.contains(".")) {
            // JWS Compacto
            String[] parts = jws.split("\\.");
            if (parts.length != 3) {
                throw new StructureException(
                    "JWS compacto inválido: esperado 3 partes separadas por '.', encontrado " + parts.length + ".");
            }
            if (parts[0].isEmpty() || parts[2].isEmpty()) {
                throw new StructureException("JWS compacto: header ou signature está vazio.");
            }
        } else {
            throw new StructureException("Formato não reconhecido: não é JWS compacto nem JWS JSON Serialization.");
        }
    }

    // -------------------------------------------------------------------------
    // Serialização FHIR
    // -------------------------------------------------------------------------

    /**
     * Serializa o resultado como recurso FHIR {@code Signature}.
     * {@code Signature.data} = base64 padrão do JWS JSON Serialization.
     */
    private String serializeSignatureResource(String jwsJsonString, long timestamp) {
        Signature sig = new Signature();
        // Tipo: assinatura de autor (código padrão ICP-Brasil)
        sig.getTypeFirstRep()
           .setSystem("urn:iso:astm:E1762-95:2013")
           .setCode("1.2.840.10065.1.12.1.1");
        sig.setWhen(new Date(timestamp * 1000L));
        sig.setData(jwsJsonString.getBytes(StandardCharsets.UTF_8));

        return fhirContext.newJsonParser().setPrettyPrint(true).encodeToString(sig);
    }

    /**
     * Constrói um {@code OperationOutcome} FHIR R4.
     */
    private String buildOperationOutcome(String severity, String code,
                                          String text, String diagnostics, String location) {
        OperationOutcome outcome = new OperationOutcome();
        outcome.setId(UUID.randomUUID().toString().substring(0, 8));

        OperationOutcome.OperationOutcomeIssueComponent issue = outcome.addIssue();
        issue.setSeverity(OperationOutcome.IssueSeverity.fromCode(severity));
        issue.setCode(OperationOutcome.IssueType.fromCode(code));
        issue.setDiagnostics(diagnostics);
        issue.setDetails(new org.hl7.fhir.r4.model.CodeableConcept().setText(text));

        if (location != null) {
            issue.addLocation(location);
            issue.addExpression(location.replace("/", "."));
        }

        outcome.getText().setStatus(org.hl7.fhir.r4.model.Narrative.NarrativeStatus.GENERATED);
        outcome.getText().setDivAsString(
            "<div xmlns=\"http://www.w3.org/1999/xhtml\"><p>" + text + "</p></div>");

        return fhirContext.newJsonParser().setPrettyPrint(true).encodeResourceToString(outcome);
    }

    // -------------------------------------------------------------------------
    // Utilitários criptográficos (simulados — sem chave privada real)
    // -------------------------------------------------------------------------

    private byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private String sha256Base64Url(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Exceções internas
    // -------------------------------------------------------------------------

    /**
     * Indica um problema estrutural no JWS recebido (distingue erro do usuário de erro do sistema).
     */
    private static class StructureException extends Exception {
        StructureException(String message) {
            super(message);
        }
    }
}
