package com.ufg.assinador.services;

import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.PrivateKey;

/**
 * Serviço de integração com dispositivos criptográficos via PKCS#11 (SunPKCS11).
 *
 * <p>Permite usar tokens físicos (smart card, e-token) ou simuladores como SoftHSM2
 * para operações de assinatura digital.</p>
 *
 * <p>Exemplo de configuração para SoftHSM2:</p>
 * <pre>
 * {
 *   "TOKEN": {
 *     "library": "/usr/lib/softhsm/libsofthsm2.so",
 *     "slot": "0",
 *     "pin": "1234",
 *     "alias": "minha-chave"
 *   }
 * }
 * </pre>
 *
 * <p>Setup do SoftHSM2 (Linux):</p>
 * <pre>
 * sudo apt-get install softhsm2
 * softhsm2-util --init-token --slot 0 --label "MeuToken" --pin 1234 --so-pin 0000
 * pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
 *             --keypairgen --key-type RSA:2048 --label "minha-chave"
 * </pre>
 */
@Service
public class Pkcs11Service {

    /**
     * Verifica se a biblioteca PKCS#11 informada é acessível e o token responde.
     *
     * @param library   caminho para a biblioteca .so / .dll do PKCS#11
     * @param slot      número do slot do token
     * @param pin       PIN de autenticação do usuário
     * @return true se o provider foi carregado e o token autenticado com sucesso
     */
    public boolean isTokenAvailable(String library, String slot, String pin) {
        try {
            Provider provider = buildProvider(library, slot);
            Security.addProvider(provider);

            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, pin.toCharArray());

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Assina dados usando a chave privada identificada pelo alias no token PKCS#11.
     *
     * @param data      dados a assinar
     * @param library   caminho para a biblioteca PKCS#11
     * @param slot      número do slot
     * @param pin       PIN do token
     * @param alias     alias da chave privada no keystore
     * @return bytes da assinatura RSA-SHA256
     * @throws Pkcs11Exception se o token não estiver disponível ou a chave não for encontrada
     */
    public byte[] sign(byte[] data, String library, String slot, String pin, String alias)
            throws Pkcs11Exception {
        try {
            Provider provider = buildProvider(library, slot);
            Security.addProvider(provider);

            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, pin.toCharArray());

            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, pin.toCharArray());
            if (privateKey == null) {
                throw new Pkcs11Exception(
                    "Chave privada com alias '" + alias + "' não encontrada no token. " +
                    "Verifique o alias com: pkcs11-tool --list-objects --login --pin " + pin);
            }

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();

        } catch (Pkcs11Exception e) {
            throw e;
        } catch (Exception e) {
            throw new Pkcs11Exception(
                "Erro ao assinar com token PKCS#11: " + e.getMessage() +
                "\nComo resolver: verifique se o token está conectado e a biblioteca está correta.", e);
        }
    }

    /**
     * Constrói um SunPKCS11 Provider a partir da biblioteca e slot informados.
     *
     * <p>Em Java 9+, o método {@code Provider.configure()} aceita uma string de configuração
     * inline que deve começar com {@code --} (duplo hífen).</p>
     */
    private Provider buildProvider(String library, String slot) throws Pkcs11Exception {
        Provider provider = Security.getProvider("SunPKCS11");
        if (provider == null) {
            throw new Pkcs11Exception(
                "Provider SunPKCS11 não disponível nesta JVM. " +
                "Certifique-se de usar JDK 21 (não JRE) com suporte a SunPKCS11.");
        }
        // Configuração inline: deve começar com "--" (Java 9+)
        String config = "--name=AssinadorPKCS11\nlibrary=" + library + "\nslot=" + slot;
        return provider.configure(config);
    }

    /**
     * Exceção específica para erros de PKCS#11, distinguindo problema do usuário de erro do sistema.
     */
    public static class Pkcs11Exception extends Exception {
        public Pkcs11Exception(String message) {
            super(message);
        }
        public Pkcs11Exception(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
