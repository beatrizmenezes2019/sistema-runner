package com.ufg.assinador.validations;

import com.ufg.assinador.enums.Operations;
import org.springframework.stereotype.Component;

@Component
public class SignatureParamsValidation {

    public Boolean createSignatureParams(String[] args){

        if (args.length < 8) {
            System.err.println("Parâmetros insuficientes para o processo de criação de assinatura.");
            return false;
        }

        return true;
    }


    public Boolean validateSignatureParams(String[] args){

        if (args.length < 2) {
            System.err.println("Parâmetros insuficientes para o processo de validação de assinatura.");
            return false;
        }
        return true;

    }

    public Operations signatureParams(String[] args){
        if (args.length < 1) {
            System.err.println("Parâmetros insuficientes.");
            return Operations.INVALID;
        }

        String operationInput = args[0].toUpperCase();

        try {
            return Operations.valueOf(operationInput);
        } catch (IllegalArgumentException e) {
            System.err.println("Operação inválida: " + operationInput + "; Operações permitidas: SIGN e VALIDATE.");
            return Operations.INVALID;
        }
    }

}
