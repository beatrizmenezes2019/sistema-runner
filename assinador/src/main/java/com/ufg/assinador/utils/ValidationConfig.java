package com.ufg.assinador.utils;
import java.util.List;

public class ValidationConfig {
    public List<String> trustStore;          // Hashes SHA-256 das ACs Raiz
    public long minCertIssueDate;            // Timestamp Unix
    public int timeoutOcsp;                  // Segundos
    public int timeoutCrl;                   // Segundos
    public int timeoutTsa;                   // Segundos
    public int ttlCache;                     // Segundos
    public int nearExpiryThresholdDays;      // Dias
    public int signatureAgeThresholdDays;    // Dias
    public String revocationPolicy;          // strict, soft-fail, warn
    public String ocspUnknownHandling;       // treat-as-revoked, treat-as-warning
    public long referenceTimestamp;          // Timestamp da validação
    public String signaturePolicyUri;        // URI da política
}