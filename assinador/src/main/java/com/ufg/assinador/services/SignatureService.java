package com.ufg.assinador.services;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.parser.IParser;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import org.hl7.fhir.r4.model.*;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Service
public class SignatureService {
    private final FhirContext fhirContext = FhirContext.forR4();

    // Ajuste no generateSignature
    public String generateSignature(String[] args) {
        try {
            byte[] bundleBytes = readFileBytes(args[1]);
            byte[] provenanceBytes = readFileBytes(args[2]);

            PrivateKey privateKey = extractPrivateKey(args[3]);

            byte[] certBytes = readFileBytes(args[4]);

            long timestamp = Long.parseLong(args[5]);
            validateTimestamp(timestamp);

            byte[] payloadToSign = combine(bundleBytes, provenanceBytes);

            String jwsCompact = signRawData(
                    privateKey,
                    payloadToSign,
                    certBytes,
                    timestamp,
                    args[7],
                    args[6]
            );

            return serializeSignatureResource(jwsCompact, timestamp, args[6]);

        } catch (Exception e) {
            return generateOperationOutcome(e);
        }
    }

    private String signRawData(PrivateKey privateKey, byte[] data, byte[] certBytes,
                               long timestamp, String pid, String estrategia) throws Exception {

        Payload payload = new Payload(data);

        List<com.nimbusds.jose.util.Base64> x5cChain = new ArrayList<>();
        x5cChain.add(com.nimbusds.jose.util.Base64.encode(certBytes));

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .x509CertChain(x5cChain)
                .customParam("sigPId", pid)
                .customParam("iat", "iat".equalsIgnoreCase(estrategia) ? timestamp : null)
                .build();

        JWSSigner signer = new RSASSASigner(privateKey);
        JWSObject jwsObject = new JWSObject(header, payload);
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    private byte[] combine(byte[] a, byte[] b) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(a);
        baos.write(b);
        return baos.toByteArray();
    }

    private byte[] readFileBytes(String path) throws Exception {
        File file = new File(path);
        if (!file.exists()) {
            throw new Exception("Arquivo não encontrado: " + path);
        }
        return Files.readAllBytes(file.toPath());
    }

    private void validateTimestamp(long timestamp) throws Exception {
        // Intervalo válido: [1751328000, 4102444800] (Julho 2025 a Dezembro 2099)
        long min = 1751328000L;
        long max = 4102444800L;

        if (timestamp < min || timestamp > max) {
            throw new Exception("Timestamp de referência fora do intervalo permitido [1751328000, 4102444800].");
        }
    }

    private String serializeSignatureResource(String jwsCompactSerialization, long timestamp, String pid) {
        Signature signature = new Signature();

        signature.getTypeFirstRep().setSystem("urn:iso:astm:E1762-95:2013");
        signature.getTypeFirstRep().setCode("1.2.840.10065.1.12.1.1");

        signature.setWhen(new Date(timestamp * 1000L));
        signature.setData(jwsCompactSerialization.getBytes(StandardCharsets.UTF_8));

        IParser parser = fhirContext.newJsonParser().setPrettyPrint(true);
        return parser.encodeToString(signature);
    }

    private String generateOperationOutcome(Exception e) {
        OperationOutcome outcome = new OperationOutcome();
        outcome.addIssue()
                .setSeverity(OperationOutcome.IssueSeverity.FATAL)
                .setCode(OperationOutcome.IssueType.EXCEPTION)
                .setDiagnostics(e.getMessage());

        return fhirContext.newJsonParser().setPrettyPrint(true).encodeResourceToString(outcome);
    }

    private PrivateKey extractPrivateKey(String jsonConfig) throws Exception {
        if (jsonConfig.startsWith("'") && jsonConfig.endsWith("'")) {
            jsonConfig = jsonConfig.substring(1, jsonConfig.length() - 1);
        }

        JSONObject config = new JSONObject(jsonConfig);

        if (config.has("TOKEN") || config.has("SMARTCARD")) {
            JSONObject hardware = config.has("TOKEN") ? config.getJSONObject("TOKEN") : config.getJSONObject("SMARTCARD");

            String libPath = config.getJSONObject("middlewareCrypto").getJSONObject("Biblioteca").getString("Caminho");

            StringBuilder sb = new StringBuilder();
            sb.append("name = HardwareDevice\n");
            sb.append("library = ").append(libPath).append("\n");

            if (hardware.has("slotId") && hardware.getInt("slotId") >= 0) {
                sb.append("slot = ").append(hardware.getInt("slotId")).append("\n");
            } else {
                sb.append("slotListIndex = 0\n");
            }

            try {
                String pkcs11Config = "--" + sb.toString();
                Provider provider = Security.getProvider("SunPKCS11").configure(pkcs11Config);
                Security.addProvider(provider);

                KeyStore ks = KeyStore.getInstance("PKCS11", provider);
                char[] pin = hardware.getString("PIN").toCharArray();
                ks.load(null, pin);

                return (PrivateKey) ks.getKey(hardware.getString("Identificador"), null);
            } catch (Exception e) {
                throw new Exception("Erro ao inicializar PKCS11 (Hardware): " + e.getMessage());
            }
        }

        if (config.has("PKCS12")) {
            JSONObject p12 = config.getJSONObject("PKCS12");
            String conteudo = p12.getString("Conteúdo");
            char[] password = p12.getString("Senha").toCharArray();

            byte[] p12Bytes;
            try {
                if (conteudo.contains("/") || conteudo.contains("\\") || conteudo.contains(":")) {
                    p12Bytes = Files.readAllBytes(Paths.get(conteudo));
                } else {
                    p12Bytes = Base64.getDecoder().decode(conteudo.replaceAll("\\s", ""));
                }

                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(new ByteArrayInputStream(p12Bytes), password);

                String alias = p12.getString("Alias");
                PrivateKey key = (PrivateKey) ks.getKey(alias, password);

                if (key == null) {
                    throw new Exception("Não foi possível encontrar a chave privada com o alias: " + alias);
                }
                return key;
            } catch (IllegalArgumentException e) {
                throw new Exception("Erro de Base64 no conteúdo PKCS12 (caractere inválido): " + e.getMessage());
            } catch (Exception e) {
                throw new Exception("Erro ao carregar arquivo PKCS12: " + e.getMessage());
            }
        }

        throw new Exception("Nenhum material criptográfico válido encontrado no JSON de entrada.");
    }

}