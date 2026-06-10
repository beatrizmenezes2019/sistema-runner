package com.ufg.assinador.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Corpo da requisição POST /validate.
 *
 * Mapeia os parâmetros posicionais do modo CLI:
 *   args[1] = jws, args[2] = configJson
 */
public class ValidateRequest {

    /** JWS compacto (header.payload.sig) ou OperationOutcome JSON contendo o JWS. */
    @JsonProperty("jws")
    public String jws;

    /** JSON de configuração de validação (trustStore, revocationPolicy, etc.). */
    @JsonProperty("configJson")
    public String configJson;
}
