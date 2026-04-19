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
		SpringApplication.run(AssinadorApplication.class, args);
	}

	@Override
	public void run(String @NonNull ... args) {

		String result = "";

		Operations op = paramsValidation.signatureParams(args);
		switch (op) {
			case SIGN -> {
				if(paramsValidation.createSignatureParams(args))
					result = engine.generateSignature(args);
			}
			case VALIDATE -> {
				if(paramsValidation.validateSignatureParams(args))
					result = engine.validate(args);
			}
		}


		System.out.print(result);
	}

}
