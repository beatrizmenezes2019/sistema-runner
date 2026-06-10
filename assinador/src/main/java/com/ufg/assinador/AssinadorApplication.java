package com.ufg.assinador;

import com.ufg.assinador.services.SignatureService;
import com.ufg.assinador.enums.Operations;
import com.ufg.assinador.validations.SignatureParamsValidation;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Ponto de entrada do assinador.
 *
 * Modos de operação:
 *   - Modo servidor (padrão): nenhum argumento → inicia servidor HTTP na porta configurada.
 *     Porta padrão: 8080. Personalizável via --server.port=XXXX ou SERVER_PORT env.
 *
 *   - Modo CLI (--local): primeiro argumento é SIGN ou VALIDATE → executa e encerra.
 *     Usado pelo CLI Go quando o servidor não está disponível.
 *
 * Exit codes:
 *   0 — sucesso
 *   1 — erro de negócio (OperationOutcome com severity=fatal)
 *   2 — erro de parâmetros (erro do usuário)
 */
@SpringBootApplication
public class AssinadorApplication implements CommandLineRunner {

    @Autowired
    private SignatureService engine;

    @Autowired
    private SignatureParamsValidation paramsValidation;

    @Autowired
    private ConfigurableApplicationContext context;

    public static void main(String[] args) {
        System.setProperty("spring.main.banner-mode", "off");
        System.setProperty("logging.level.root", "OFF");
        System.setProperty("logging.level.org.springframework", "OFF");
        SpringApplication.run(AssinadorApplication.class, args);
    }

    @Override
    public void run(String @NonNull ... args) {
        // Modo servidor: sem argumentos (ou apenas flags do Spring como --server.port)
        // Filtra args do Spring antes de avaliar
        String[] appArgs = filterSpringArgs(args);

        if (appArgs.length == 0) {
            // Modo servidor — o contexto Spring permanece ativo (servidor HTTP rodando)
            int port = Integer.parseInt(
                System.getProperty("server.port",
                    context.getEnvironment().getProperty("server.port", "8080"))
            );
            System.out.printf("[assinador] Modo servidor iniciado na porta %d. GET /health para verificar.%n", port);
            return;
        }

        // Modo CLI — executa operação e encerra o contexto Spring
        runCliMode(appArgs);
    }

    private void runCliMode(String[] args) {
        Operations op = paramsValidation.signatureParams(args);

        String result;
        switch (op) {
            case SIGN -> {
                if (!paramsValidation.createSignatureParams(args)) {
                    context.close();
                    System.exit(2);
                    return;
                }
                result = engine.generateSignature(args);
            }
            case VALIDATE -> {
                if (!paramsValidation.validateSignatureParams(args)) {
                    context.close();
                    System.exit(2);
                    return;
                }
                result = engine.validate(args);
            }
            default -> {
                context.close();
                System.exit(2);
                return;
            }
        }

        System.out.print(result);
        context.close();

        if (result != null && result.contains("\"fatal\"")) {
            System.exit(1);
        }
        System.exit(0);
    }

    /**
     * Remove flags do Spring Boot (--server.port, --spring.*, etc.) do array de args
     * para que a lógica de negócio veja apenas os argumentos da aplicação.
     */
    private String[] filterSpringArgs(String[] args) {
        return java.util.Arrays.stream(args)
            .filter(a -> !a.startsWith("--server.") && !a.startsWith("--spring."))
            .toArray(String[]::new);
    }
}
