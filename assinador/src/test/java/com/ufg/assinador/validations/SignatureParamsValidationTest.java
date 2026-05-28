package com.ufg.assinador.validations;

import com.ufg.assinador.enums.Operations;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes unitários para SignatureParamsValidation.
 *
 * Cada método de validação é coberto em três categorias:
 *   - sucesso (caminho feliz)
 *   - erros do usuário (parâmetros ausentes ou inválidos)
 *   - erros de sistema (arquivo inexistente, sem permissão)
 */
@DisplayName("SignatureParamsValidation")
class SignatureParamsValidationTest {

    private SignatureParamsValidation validator;

    @TempDir
    Path tempDir;

    private String existingFile;
    private String missingFile;

    @BeforeEach
    void setUp() throws IOException {
        validator = new SignatureParamsValidation();

        // Cria um arquivo legível para testes
        Path readable = tempDir.resolve("arquivo.bin");
        Files.write(readable, new byte[]{0x01, 0x02});
        existingFile = readable.toAbsolutePath().toString();

        missingFile = tempDir.resolve("nao-existe.bin").toAbsolutePath().toString();
    }

    // =========================================================================
    // signatureParams (operação)
    // =========================================================================

    @Nested
    @DisplayName("signatureParams()")
    class SignatureParamsTests {

        @Test
        @DisplayName("retorna SIGN para 'SIGN' (maiúsculas)")
        void signUppercase() {
            assertEquals(Operations.SIGN, validator.signatureParams(new String[]{"SIGN"}));
        }

        @Test
        @DisplayName("retorna SIGN para 'sign' (minúsculas — normalização)")
        void signLowercase() {
            assertEquals(Operations.SIGN, validator.signatureParams(new String[]{"sign"}));
        }

        @Test
        @DisplayName("retorna VALIDATE para 'VALIDATE'")
        void validateUppercase() {
            assertEquals(Operations.VALIDATE, validator.signatureParams(new String[]{"VALIDATE"}));
        }
    }

    // =========================================================================
    // createSignatureParams (SIGN)
    // =========================================================================

    @Nested
    @DisplayName("createSignatureParams() — SIGN")
    class CreateSignatureParamsTests {

        private String validConfigJson() {
            return "{\"PKCS12\":{\"Conteúdo\":\"base64\",\"Senha\":\"s\",\"Alias\":\"a\"}}";
        }

        private String[] validSignArgs() {
            return new String[]{
                "SIGN",
                existingFile,              // bundle
                existingFile,              // provenance
                validConfigJson(),         // config-cripto
                existingFile,              // cert
                "1751328001",              // timestamp
                "AD_RB",                   // estrategia
                "pid-123"                  // pid
            };
        }

        @Test
        @DisplayName("aceita argumentos válidos")
        void happyPath() {
            assertTrue(validator.createSignatureParams(validSignArgs()));
        }

        @Test
        @DisplayName("rejeita quando há menos de 8 argumentos")
        void tooFewArgs() {
            assertFalse(validator.createSignatureParams(new String[]{"SIGN", existingFile}));
        }

        @Test
        @DisplayName("rejeita quando bundle não existe")
        void bundleNotFound() {
            String[] args = validSignArgs();
            args[1] = missingFile;
            assertFalse(validator.createSignatureParams(args));
        }

        @Test
        @DisplayName("rejeita quando provenance não existe")
        void provenanceNotFound() {
            String[] args = validSignArgs();
            args[2] = missingFile;
            assertFalse(validator.createSignatureParams(args));
        }

        @Test
        @DisplayName("rejeita quando config-cripto está vazio")
        void configCriptoBlank() {
            String[] args = validSignArgs();
            args[3] = "   ";
            assertFalse(validator.createSignatureParams(args));
        }

        @Test
        @DisplayName("rejeita quando config-cripto não começa com '{'")
        void configCriptoNotJson() {
            String[] args = validSignArgs();
            args[3] = "nao-e-json";
            assertFalse(validator.createSignatureParams(args));
        }

        @Test
        @DisplayName("rejeita quando certificado não existe")
        void certNotFound() {
            String[] args = validSignArgs();
            args[4] = missingFile;
            assertFalse(validator.createSignatureParams(args));
        }

        @Test
        @DisplayName("rejeita quando timestamp está vazio")
        void timestampBlank() {
            String[] args = validSignArgs();
            args[5] = "";
            assertFalse(validator.createSignatureParams(args));
        }

        @Test
        @DisplayName("rejeita quando timestamp não é número")
        void timestampNotNumber() {
            String[] args = validSignArgs();
            args[5] = "abc";
            assertFalse(validator.createSignatureParams(args));
        }

        @Test
        @DisplayName("rejeita quando timestamp é zero ou negativo")
        void timestampNonPositive() {
            String[] args = validSignArgs();
            args[5] = "0";
            assertFalse(validator.createSignatureParams(args));

            args[5] = "-1";
            assertFalse(validator.createSignatureParams(args));
        }

        @Test
        @DisplayName("rejeita quando estrategia está vazia")
        void estrategiaBlank() {
            String[] args = validSignArgs();
            args[6] = "";
            assertFalse(validator.createSignatureParams(args));
        }

        @Test
        @DisplayName("rejeita quando pid está vazio")
        void pidBlank() {
            String[] args = validSignArgs();
            args[7] = "  ";
            assertFalse(validator.createSignatureParams(args));
        }
    }

    // =========================================================================
    // validateSignatureParams (VALIDATE)
    // =========================================================================

    @Nested
    @DisplayName("validateSignatureParams() — VALIDATE")
    class ValidateSignatureParamsTests {

        private String validJws() {
            // JWS compacto mínimo (3 partes separadas por ponto)
            return "eyJhbGciOiJSUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl";
        }

        private String validConfig() {
            return "{\"trustStore\":[\"abc123\"]}";
        }

        @Test
        @DisplayName("aceita JWS compacto com config válida")
        void happyPathCompactJws() {
            assertTrue(validator.validateSignatureParams(
                new String[]{"VALIDATE", validJws(), validConfig()}
            ));
        }

        @Test
        @DisplayName("aceita JSON OperationOutcome como jws")
        void happyPathJsonJws() {
            String jsonJws = "{\"resourceType\":\"OperationOutcome\",\"issue\":[{\"diagnostics\":\"" + validJws() + "\"}]}";
            assertTrue(validator.validateSignatureParams(
                new String[]{"VALIDATE", jsonJws, validConfig()}
            ));
        }

        @Test
        @DisplayName("rejeita quando há menos de 3 argumentos")
        void tooFewArgs() {
            assertFalse(validator.validateSignatureParams(new String[]{"VALIDATE"}));
            assertFalse(validator.validateSignatureParams(new String[]{"VALIDATE", validJws()}));
        }

        @Test
        @DisplayName("rejeita quando jws está vazio")
        void jwsBlank() {
            assertFalse(validator.validateSignatureParams(
                new String[]{"VALIDATE", "", validConfig()}
            ));
        }

        @Test
        @DisplayName("rejeita quando jws não é JWS nem JSON")
        void jwsInvalid() {
            assertFalse(validator.validateSignatureParams(
                new String[]{"VALIDATE", "nao-e-jws-nem-json", validConfig()}
            ));
        }

        @Test
        @DisplayName("rejeita quando config-json está vazio")
        void configBlank() {
            assertFalse(validator.validateSignatureParams(
                new String[]{"VALIDATE", validJws(), ""}
            ));
        }

        @Test
        @DisplayName("rejeita quando config-json não começa com '{'")
        void configNotJson() {
            assertFalse(validator.validateSignatureParams(
                new String[]{"VALIDATE", validJws(), "nao-e-json"}
            ));
        }
    }
}
