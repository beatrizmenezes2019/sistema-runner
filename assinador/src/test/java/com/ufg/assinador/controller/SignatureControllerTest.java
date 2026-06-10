package com.ufg.assinador.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Testes de integração dos endpoints REST do assinador no modo servidor.
 *
 * Usa MockMvc para testar a camada HTTP sem subir um servidor real,
 * validando mapeamento de rotas, content-type, status codes e estrutura das respostas.
 */
@SpringBootTest
@DisplayName("SignatureController — endpoints HTTP")
class SignatureControllerTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    // =========================================================================
    // GET /health
    // =========================================================================

    @Nested
    @DisplayName("GET /health")
    class HealthTests {

        @Test
        @DisplayName("retorna 200 OK com status UP")
        void returnsUp() throws Exception {
            mvc.perform(get("/health").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("assinador"));
        }
    }

    // =========================================================================
    // POST /sign
    // =========================================================================

    @Nested
    @DisplayName("POST /sign")
    class SignTests {

        @Test
        @DisplayName("retorna 400 quando corpo está ausente")
        void missingBody() throws Exception {
            mvc.perform(post("/sign")
                    .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("retorna 400 quando campos obrigatórios estão ausentes")
        void missingRequiredFields() throws Exception {
            String body = """
                {
                  "bundle": "",
                  "provenance": "",
                  "configCripto": "",
                  "cert": "",
                  "timestamp": "",
                  "estrategia": "",
                  "pid": ""
                }
                """;

            mvc.perform(post("/sign")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.resourceType").value("OperationOutcome"));
        }

        @Test
        @DisplayName("retorna 400 quando bundle aponta para arquivo inexistente")
        void bundleNotFound() throws Exception {
            String body = """
                {
                  "bundle": "/nao/existe/bundle.json",
                  "provenance": "/nao/existe/provenance.json",
                  "configCripto": "{\\"PKCS12\\":{\\"Conteúdo\\":\\"x\\",\\"Senha\\":\\"s\\",\\"Alias\\":\\"a\\"}}",
                  "cert": "/nao/existe/cert.der",
                  "timestamp": "1751328001",
                  "estrategia": "AD_RB",
                  "pid": "pid-123"
                }
                """;

            mvc.perform(post("/sign")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.resourceType").value("OperationOutcome"));
        }

        @Test
        @DisplayName("retorna Content-Type application/json")
        void returnsJson() throws Exception {
            String body = """
                {
                  "bundle": "",
                  "provenance": "",
                  "configCripto": "{}",
                  "cert": "",
                  "timestamp": "abc",
                  "estrategia": "",
                  "pid": ""
                }
                """;

            mvc.perform(post("/sign")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }
    }

    // =========================================================================
    // POST /validate
    // =========================================================================

    @Nested
    @DisplayName("POST /validate")
    class ValidateTests {

        @Test
        @DisplayName("retorna 400 quando corpo está ausente")
        void missingBody() throws Exception {
            mvc.perform(post("/validate")
                    .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("retorna 400 quando jws está vazio")
        void emptyJws() throws Exception {
            String body = """
                {
                  "jws": "",
                  "configJson": "{\\"trustStore\\":[\\"abc123\\"]}"
                }
                """;

            mvc.perform(post("/validate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.resourceType").value("OperationOutcome"));
        }

        @Test
        @DisplayName("retorna 400 quando configJson não é JSON")
        void invalidConfigJson() throws Exception {
            String body = """
                {
                  "jws": "eyJ.cGF5.c2ln",
                  "configJson": "nao-e-json"
                }
                """;

            mvc.perform(post("/validate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.resourceType").value("OperationOutcome"));
        }

        @Test
        @DisplayName("retorna Content-Type application/json para qualquer resposta")
        void returnsJson() throws Exception {
            String body = """
                {
                  "jws": "",
                  "configJson": ""
                }
                """;

            mvc.perform(post("/validate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }
    }

    // =========================================================================
    // Rotas inexistentes
    // =========================================================================

    @Nested
    @DisplayName("Rotas inexistentes")
    class NotFoundTests {

        @Test
        @DisplayName("retorna 404 para rota desconhecida")
        void unknownRoute() throws Exception {
            mvc.perform(get("/nao-existe"))
                .andExpect(status().isNotFound());
        }
    }
}
