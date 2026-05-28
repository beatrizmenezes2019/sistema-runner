package com.ufg.assinador;

import com.ufg.assinador.enums.Operations;
import com.ufg.assinador.services.SignatureService;
import com.ufg.assinador.validations.SignatureParamsValidation;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Verifica que o contexto Spring carrega corretamente.
 *
 * Problema original: AssinadorApplication implementa CommandLineRunner.
 * Quando @SpringBootTest sobe o contexto sem argumentos, run() é chamado
 * com args vazio → System.exit(2) → no CI (Maven Surefire com JVM forkada)
 * o processo morre e a suite inteira falha.
 *
 * Solução:
 *  1. Passar args válidos para @SpringBootTest(args = ...) para evitar o
 *     branch "nenhum argumento" que chama System.exit.
 *  2. Substituir SignatureParamsValidation e SignatureService por mocks
 *     pré-configurados via @TestConfiguration/@Primary, evitando que
 *     qualquer lógica de negócio real seja executada durante o boot de teste.
 */
@SpringBootTest(args = {
        "VALIDATE",
        "eyJhbGciOiJSUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl",
        "{\"trustStore\":[]}"
})
class AssinadorApplicationTests {

    /**
     * Beans de teste que substituem os componentes reais no contexto Spring.
     * São criados antes de run() ser invocado, por isso podem ser pré-configurados.
     */
    @TestConfiguration
    static class TestConfig {

        @Bean
        @Primary
        SignatureParamsValidation signatureParamsValidation() {
            SignatureParamsValidation mock = Mockito.mock(SignatureParamsValidation.class);
            // run() chama signatureParams() e validateSignatureParams(); ambos precisam
            // de retornos válidos para evitar chamadas a System.exit.
            when(mock.signatureParams(any())).thenReturn(Operations.VALIDATE);
            when(mock.validateSignatureParams(any())).thenReturn(true);
            return mock;
        }

        @Bean
        @Primary
        SignatureService signatureService() {
            SignatureService mock = Mockito.mock(SignatureService.class);
            // Retorna JSON sem "fatal" para que System.exit(1) não seja chamado.
            when(mock.validate(any())).thenReturn("{\"resourceType\":\"OperationOutcome\"}");
            return mock;
        }
    }

    @Test
    void contextLoads() {
        // Verifica apenas que o contexto Spring inicializa sem erros.
    }
}
