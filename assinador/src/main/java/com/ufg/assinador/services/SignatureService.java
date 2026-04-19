package com.ufg.assinador.services;

import ca.uhn.fhir.context.FhirContext;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.ufg.assinador.enums.RevocationStatus;
import com.ufg.assinador.utils.ValidationConfig;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.*;
import org.hl7.fhir.r4.model.OperationOutcome;
import org.hl7.fhir.r4.model.Signature;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class SignatureService {
    private final FhirContext fhirContext = FhirContext.forR4();

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

            return generateOperationOutcome(
                    "information",
                    "informational",
                    "Assinatura gerada com sucesso",
                    jwsCompact,
                    null
            );

        } catch (Exception e) {
            return generateOperationOutcome("fatal", "exception", "Erro na geração da assinatura", e.getMessage(), null);
        }
    }

    private String signRawData(PrivateKey privateKey, byte[] data, byte[] certBytes,
                               long timestamp, String pid, String estrategia) throws Exception {

        com.nimbusds.jose.util.Base64 x5cCert = com.nimbusds.jose.util.Base64.encode(certBytes);
        List<com.nimbusds.jose.util.Base64> x5cChain = Collections.singletonList(x5cCert);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .x509CertChain(x5cChain)
                .customParam("sigPId", pid)
                .customParam("iat", timestamp)
                .build();

        Payload payload = new Payload(data);

        JWSSigner signer = new RSASSASigner(privateKey);
        JWSObject jwsObject = new JWSObject(header, payload);
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public String validate(String[] args) {
        try {
            if (args.length < 3) throw new Exception("Argumentos insuficientes para validação.");
            String base64Jws = args[1];
            String configJson = args[2];
            JSONObject config = new JSONObject(configJson);

            return proceedToParsing(base64Jws, config);
        } catch (Exception e) {
            return generateOperationOutcome("fatal", "exception", "Erro interno na validação", e.getMessage(), null);
        }
    }

    private String proceedToParsing(String base64Jws, JSONObject config) {
        try {
            String rawInput = base64Jws.trim().replaceAll("\\s", "");

            if (rawInput.startsWith("{")) {
                JSONObject jsonInput = new JSONObject(rawInput);
                if (jsonInput.has("issue")) {
                    rawInput = jsonInput.getJSONArray("issue")
                            .getJSONObject(0)
                            .getString("diagnostics");
                }
            }

            String protectedB64, payloadB64, signatureB64;

            if (rawInput.contains(".") && !rawInput.startsWith("{")) {
                String[] parts = rawInput.split("\\.");
                if (parts.length != 3) throw new Exception("Estrutura JWS Compacta inválida. Deve conter 3 partes separadas por pontos.");
                protectedB64 = parts[0];
                payloadB64 = parts[1];
                signatureB64 = parts[2];
            } else {
                JSONObject jwsJson = new JSONObject(rawInput);
                JSONObject sigObject = jwsJson.getJSONArray("signatures").getJSONObject(0);
                protectedB64 = sigObject.getString("protected");
                payloadB64 = jwsJson.getString("payload");
                signatureB64 = sigObject.getString("signature");
            }

            String protectedJsonStr = new String(Base64.getUrlDecoder().decode(protectedB64), StandardCharsets.UTF_8);
            JSONObject protectedHeader = new JSONObject(protectedJsonStr);

            return performCryptographicValidation(payloadB64, protectedB64, protectedHeader, signatureB64, config);

        } catch (Exception e) {
            return generateOperationOutcome("fatal", "structure", "Erro no parsing do JWS", e.getMessage(), "Signature.data");
        }
    }

    private String performCryptographicValidation(String payloadB64, String protectedB64,
                                                  JSONObject protectedHeader, String signatureB64,
                                                  JSONObject configObject) {
        try {
            ValidationConfig config = convertToValidationConfig(configObject);

            if (!protectedHeader.has("x5c")) throw new Exception("Header 'x5c' não encontrado.");
            JSONArray x5c = protectedHeader.getJSONArray("x5c");

            String firstCertStr = x5c.getString(0).replaceAll("\\s", "");
            if (firstCertStr.isEmpty()) throw new Exception("O certificado no header x5c está vazio.");

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] certBytes = Base64.getMimeDecoder().decode(firstCertStr);
            X509Certificate signerCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

            String rootCertStr = x5c.getString(x5c.length() - 1).replaceAll("\\s", "");
            byte[] rootCertBytes = Base64.getMimeDecoder().decode(rootCertStr);
            String rootHash = calculateSHA256Hex(rootCertBytes);

            if (!config.trustStore.contains(rootHash.toLowerCase())) {
                return generateOperationOutcome("fatal", "security", "Certificado Raiz não confiável", "CONFIG.TRUST-STORE-NOT-FOUND", "protected/x5c");
            }

            String signingInput = protectedB64 + "." + payloadB64;
            byte[] dataToVerify = signingInput.getBytes(StandardCharsets.US_ASCII);
            byte[] sigBytes = Base64.getUrlDecoder().decode(signatureB64.replaceAll("\\s", ""));

            if (!verifySignature(signerCert, protectedHeader.getString("alg"), dataToVerify, sigBytes)) {
                return generateOperationOutcome("fatal", "security", "Assinatura digital inválida", "CRYPTO.SIGNATURE-INVALID", "signature");
            }

            return proceedToRevocationValidation(signerCert, config);

        } catch (Exception e) {
            return generateOperationOutcome("fatal", "exception", "Falha na validação criptográfica", e.getMessage(), null);
        }
    }

    private String proceedToRevocationValidation(X509Certificate cert, ValidationConfig config) {
        try {
            boolean isRevoked = checkRevocationStatus(cert, config);

            if (isRevoked) {
                return generateOperationOutcome("fatal", "security", "Certificado revogado", "CERT.REVOKED", "signerCertificate");
            }

            return generateOperationOutcome("information", "informational", "Assinatura validada com sucesso", "SUCCESS", null);

        } catch (RuntimeException e) {
            return generateOperationOutcome("fatal", "security", "Falha de comunicação na revogação", e.getMessage(), null);
        }
    }

    private String generateOperationOutcome(String severity, String code, String text, String diagnostics, String location) {
        OperationOutcome outcome = new OperationOutcome();
        outcome.setId(UUID.randomUUID().toString().substring(0, 5));

        OperationOutcome.OperationOutcomeIssueComponent issue = outcome.addIssue();
        issue.setSeverity(OperationOutcome.IssueSeverity.fromCode(severity));
        issue.setCode(OperationOutcome.IssueType.fromCode(code));
        issue.setDiagnostics(diagnostics);
        issue.setDetails(new org.hl7.fhir.r4.model.CodeableConcept().setText(text));

        if (location != null) {
            issue.addLocation(location);
            issue.addExpression(location.replace("/", ""));
        }

        outcome.getText().setStatus(org.hl7.fhir.r4.model.Narrative.NarrativeStatus.GENERATED);
        outcome.getText().setDivAsString("<div xmlns=\"http://www.w3.org/1999/xhtml\"><p>" + text + "</p></div>");

        return fhirContext.newJsonParser().setPrettyPrint(true).encodeResourceToString(outcome);
    }

    private String serializeSignatureResource(String jwsCompact, long timestamp) {
        Signature sig = new Signature();
        sig.getTypeFirstRep().setSystem("urn:iso:astm:E1762-95:2013").setCode("1.2.840.10065.1.12.1.1");
        sig.setWhen(new Date(timestamp * 1000L));
        sig.setData(jwsCompact.getBytes(StandardCharsets.UTF_8));

        return fhirContext.newJsonParser().setPrettyPrint(true).encodeToString(sig);
    }

    private String calculateSHA256Hex(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private boolean verifySignature(X509Certificate cert, String alg, byte[] data, byte[] sigBytes) throws Exception {
        String javaAlg = "SHA256withRSA";
        java.security.Signature sig = java.security.Signature.getInstance(javaAlg);
        sig.initVerify(cert.getPublicKey());
        sig.update(data);
        return sig.verify(sigBytes);
    }

    private byte[] combine(byte[] a, byte[] b) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(a);
        baos.write(b);
        return baos.toByteArray();
    }

    private byte[] readFileBytes(String path) throws Exception {
        return Files.readAllBytes(Paths.get(path));
    }

    private void validateTimestamp(long ts) throws Exception {
        if (ts < 1751328000L || ts > 4102444800L) throw new Exception("Timestamp fora do intervalo permitido.");
    }

    private ValidationConfig convertToValidationConfig(JSONObject config) {
        ValidationConfig cfg = new ValidationConfig();
        cfg.trustStore = new ArrayList<>();
        JSONArray tsArray = config.optJSONArray("trustStore");
        if (tsArray != null) {
            for (int i = 0; i < tsArray.length(); i++) cfg.trustStore.add(tsArray.getString(i).toLowerCase());
        }
        cfg.minCertIssueDate = config.optLong("minCertIssueDate", 1751328000L);
        cfg.referenceTimestamp = config.optLong("referenceTimestamp", System.currentTimeMillis() / 1000);
        cfg.timeoutOcsp = config.optInt("timeoutOcsp", 30);
        cfg.timeoutCrl = config.optInt("timeoutCrl", 30);
        cfg.revocationPolicy = config.optString("revocationPolicy", "strict");
        cfg.ocspUnknownHandling = config.optString("ocspUnknownHandling", "treat-as-revoked");
        return cfg;
    }

    private boolean checkRevocationStatus(X509Certificate cert, ValidationConfig config) {
        try {
            String ocspUrl = getOcspUrl(cert);
            if (ocspUrl != null) {
                RevocationStatus status = checkOCSP(cert, ocspUrl, config.timeoutOcsp);
                if (status == RevocationStatus.GOOD) return false;
                if (status == RevocationStatus.REVOKED) return true;
                if (status == RevocationStatus.UNKNOWN) return config.ocspUnknownHandling.equals("treat-as-revoked");
            }
            return checkCRL(cert, config.timeoutCrl);
        } catch (Exception e) {
            if (config.revocationPolicy.equals("strict")) throw new RuntimeException("Falha na consulta de revogação: " + e.getMessage());
            return false;
        }
    }

    private RevocationStatus checkOCSP(X509Certificate cert, String url, int timeout) { return RevocationStatus.GOOD; }

    private boolean checkCRL(X509Certificate cert, int timeout) throws Exception {
        List<String> crlUrls = getCrlDistributionPoints(cert);
        for (String url : crlUrls) {
            URLConnection conn = new URL(url).openConnection();
            conn.setConnectTimeout(timeout * 1000);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(conn.getInputStream());
            if (crl.isRevoked(cert)) return true;
        }
        return false;
    }

    private String getOcspUrl(X509Certificate cert) {
        byte[] aia = cert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess.getId());
        if (aia == null) return null;
        try {
            byte[] octets = ((org.bouncycastle.asn1.ASN1OctetString) ASN1Primitive.fromByteArray(aia)).getOctets();
            AuthorityInformationAccess info = AuthorityInformationAccess.getInstance(ASN1Primitive.fromByteArray(octets));
            for (AccessDescription ad : info.getAccessDescriptions()) {
                if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    return ((DERIA5String) ad.getAccessLocation().getName()).getString();
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private List<String> getCrlDistributionPoints(X509Certificate cert) {
        List<String> urls = new ArrayList<>();
        byte[] crlDP = cert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId());
        if (crlDP == null) return urls;
        try {
            byte[] octets = ((org.bouncycastle.asn1.ASN1OctetString) ASN1Primitive.fromByteArray(crlDP)).getOctets();
            CRLDistPoint dist = CRLDistPoint.getInstance(ASN1Primitive.fromByteArray(octets));
            for (DistributionPoint dp : dist.getDistributionPoints()) {
                GeneralName[] names = GeneralNames.getInstance(dp.getDistributionPoint().getName()).getNames();
                for (GeneralName name : names) urls.add(((DERIA5String) name.getName()).getString());
            }
        } catch (Exception ignored) {}
        return urls;
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
            } catch (Exception e) {
                throw new Exception("Erro ao carregar arquivo PKCS12: " + e.getMessage());
            }
        }

        throw new Exception("Nenhum material criptográfico válido encontrado no JSON de entrada.");
    }
}