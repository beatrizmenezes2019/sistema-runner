package com.ufg.assinador.enums;

public enum RevocationStatus {
    GOOD,      // Certificado válido/ativo
    REVOKED,   // Certificado cancelado/revogado
    UNKNOWN    // O servidor não conhece o certificado ou está fora do ar
}