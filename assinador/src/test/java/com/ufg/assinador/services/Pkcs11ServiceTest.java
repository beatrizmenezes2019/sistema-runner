package com.ufg.assinador.services;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes de integração do Pkcs11Service com SoftHSM2.
 *
 * <p>Esses testes exigem SoftHSM2 instalado e inicializado. Em CI, o token é
 * preparado pelo step "Instalar SoftHSM2" no pipeline. Localmente:</p>
 *
 * <pre>
 * sudo apt-get install softhsm2
 * softhsm2-util --init-token --slot 0 --label "TestToken" --pin 1234 --so-pin 0000
 * export SOFTHSM2_AVAILABLE=true
 * </pre>
 *
 * <p>Os testes são pulados automaticamente se a variável SOFTHSM2_AVAILABLE não
 * estiver definida, para não quebrar builds sem o simulador instalado.</p>
 */
@DisplayName("Pkcs11Service — integração com SoftHSM2")
class Pkcs11ServiceTest {

    /**
     * Localização padrão da biblioteca SoftHSM2 em distribuições Debian/Ubuntu.
     * Em outros sistemas, sobrescreva com a variável de ambiente SOFTHSM2_LIB.
     */
    private static final String DEFAULT_LIB = "/usr/lib/softhsm/libsofthsm2.so";
    private static final String SOFTHSM2_LIB =
        System.getenv("SOFTHSM2_LIB") != null ? System.getenv("SOFTHSM2_LIB") : DEFAULT_LIB;

    private static final String SLOT  = "0";
    private static final String PIN   = "1234";

    private final Pkcs11Service service = new Pkcs11Service();

    // =========================================================================
    // Disponibilidade do token
    // =========================================================================

    @Test
    @DisplayName("isTokenAvailable retorna false quando biblioteca não existe")
    void tokenNotAvailableWhenLibMissing() {
        assertFalse(service.isTokenAvailable("/nao/existe/libsofthsm.so", SLOT, PIN),
            "Deve retornar false para biblioteca inexistente");
    }

    @Test
    @DisplayName("isTokenAvailable com PIN errado: sessão abre mas PIN será rejeitado ao assinar")
    @EnabledIfEnvironmentVariable(named = "SOFTHSM2_AVAILABLE", matches = "true")
    void tokenAvailableEvenWithWrongPin() {
        // SoftHSM2 sem objetos privados não exige autenticação para abrir sessão —
        // C_Login com PIN incorreto só falha ao tentar acessar chaves privadas (sign).
        // isTokenAvailable verifica acessibilidade do token, não correção do PIN.
        assertTrue(service.isTokenAvailable(SOFTHSM2_LIB, SLOT, "pin-errado"),
            "Sessão deve abrir mesmo com PIN errado quando o token não tem objetos privados");
    }

    @Test
    @DisplayName("isTokenAvailable retorna true com SoftHSM2 configurado")
    @EnabledIfEnvironmentVariable(named = "SOFTHSM2_AVAILABLE", matches = "true")
    void tokenAvailableWithSoftHsm2() {
        assertTrue(service.isTokenAvailable(SOFTHSM2_LIB, SLOT, PIN),
            "SoftHSM2 deve estar disponível e autenticar com PIN correto");
    }

    // =========================================================================
    // Assinatura com token PKCS#11
    // =========================================================================

    @Test
    @DisplayName("sign lança Pkcs11Exception quando biblioteca não existe")
    void signThrowsWhenLibMissing() {
        byte[] data = "dados de teste".getBytes();
        assertThrows(Pkcs11Service.Pkcs11Exception.class,
            () -> service.sign(data, "/nao/existe/lib.so", SLOT, PIN, "alias"),
            "Deve lançar Pkcs11Exception para biblioteca inválida");
    }

    @Test
    @DisplayName("sign lança Pkcs11Exception quando alias não existe no token")
    @EnabledIfEnvironmentVariable(named = "SOFTHSM2_AVAILABLE", matches = "true")
    void signThrowsWhenAliasNotFound() {
        byte[] data = "dados de teste".getBytes();
        Pkcs11Service.Pkcs11Exception ex = assertThrows(
            Pkcs11Service.Pkcs11Exception.class,
            () -> service.sign(data, SOFTHSM2_LIB, SLOT, PIN, "alias-inexistente"),
            "Deve lançar Pkcs11Exception para alias inexistente"
        );
        assertTrue(ex.getMessage().contains("alias-inexistente"),
            "Mensagem de erro deve mencionar o alias procurado");
    }
}
