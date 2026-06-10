package com.ufg.assinador.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Corpo da requisição POST /sign.
 *
 * Mapeia exatamente os parâmetros posicionais do modo CLI:
 *   args[1] = bundle, args[2] = provenance, args[3] = configCripto,
 *   args[4] = cert, args[5] = timestamp, args[6] = estrategia, args[7] = pid
 *
 * Os campos bundle, provenance e cert aceitam tanto caminhos de arquivo
 * quanto conteúdo base64 (prefixo "base64:").
 */
public class SignRequest {

    /** Caminho ou conteúdo base64 do Bundle FHIR. */
    @JsonProperty("bundle")
    public String bundle;

    /** Caminho ou conteúdo base64 do Provenance FHIR. */
    @JsonProperty("provenance")
    public String provenance;

    /** JSON de material criptográfico (PKCS12 ou TOKEN). */
    @JsonProperty("configCripto")
    public String configCripto;

    /** Caminho ou conteúdo base64 do certificado .der. */
    @JsonProperty("cert")
    public String cert;

    /** Timestamp Unix em segundos. */
    @JsonProperty("timestamp")
    public String timestamp;

    /** Estratégia de assinatura (ex.: AD_RB, AD_RT). */
    @JsonProperty("estrategia")
    public String estrategia;

    /** Identificador do assinante (PID). */
    @JsonProperty("pid")
    public String pid;
}
