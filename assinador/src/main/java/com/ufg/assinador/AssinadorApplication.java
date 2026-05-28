package com.ufg.assinador;

import com.ufg.assinador.services.SignatureService;
import com.ufg.assinador.enums.Operations;
import com.ufg.assinador.validations.SignatureParamsValidation;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AssinadorApplication implements CommandLineRunner {

    @Autowired
    private SignatureService engine;

    @Autowired
    private SignatureParamsValidation paramsValidation;

    public static void main(String[] args) {
        System.setProperty("spring.main.banner-mode", "off");
        System.setProperty("logging.level.root", "OFF");
        SpringApplication.run(AssinadorApplication.class, args);
    }

    @Override
    public void run(String @NonNull ... args) {
        if (args.length == 0) {
            System.err.println("[ERRO] Nenhum argumento fornecido.");
            System.err.println("[USO]  java -jar assinador.jar SIGN <bundle> <provenance> <config-cripto-json> <cert> <timestamp> <estrategia> <pid>");
            System.err.println("       java -jar assinador.jar VALIDATE <jws> <config-json>");
            System.exit(2);
        }

        Operations op = paramsValidation.signatureParams(args);

        String result;
        switch (op) {
            case SIGN -> {
                if (!paramsValidation.createSignatureParams(args)) {
                    System.exit(2);
                }
                result = engine.generateSignature(args);
            }
            case VALIDATE -> {
                if (!paramsValidation.validateSignatureParams(args)) {
                    System.exit(2);
                }
                result = engine.validate(args);
            }
            default -> {
                System.exit(2);
                return;
            }
        }

        System.out.print(result);

        if (result != null && result.contains("\"fatal\"")) {
            System.exit(1);
        }
    }
}
