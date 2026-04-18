package com.ufg.assinador;

import com.ufg.assinador.services.SignatureService;
import com.ufg.assinador.enums.Operations;
import org.hl7.fhir.r4.model.OperationDefinition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AssinadorApplication implements CommandLineRunner {

	@Autowired
	private SignatureService engine;

	public static void main(String[] args) {
		SpringApplication.run(AssinadorApplication.class, args);
	}

	@Override
	public void run(String... args) {
		if (args.length < 8) {
			System.err.println("Parâmetros insuficientes.");
			return;
		}

		String operationInput = args[0].toUpperCase();
		String result = "";

		try {
			Operations op = Operations.valueOf(operationInput);

			switch (op) {
				case SIGN -> result = engine.generateSignature(args);
				case VALIDATE -> result = "Validando...";
			}
		} catch (IllegalArgumentException e) {
			System.err.println("Operação inválida: " + operationInput);
		}

		System.out.print(result);
	}

}
