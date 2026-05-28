package com.ufg.assinador.validations;

import com.ufg.assinador.enums.Operations;
import com.ufg.assinador.validations.ValidationResult;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Valida os parâmetros recebidos via linha de comando antes de qualquer processamento.
 *
 * Contrato de argumentos SIGN  (índices 0..7):
 *   0: "SIGN"
 *   1: caminho para bundle (arquivo)
 *   2: caminho para provenance (arquivo)
 *   3: JSON de material criptográfico (PKCS12 ou TOKEN)
 *   4: caminho para certificado (arquivo)
 *   5: timestamp Unix (long, > 0)
 *   6: estratégia de assinatura
 *   7: PID do assinante
 *
 * Contrato de argumentos VALIDATE (índices 0..2):
 *   0: "VALIDATE"
 *   1: JWS compacto ou JSON OperationOutcome com o JWS em diagnostics
 *   2: JSON de configuração de validação
 */
@Component
public class SignatureParamsValidation {

    // -------------------------------------------------------------------------
    // Operação
    // -------------------------------------------------------------------------

    public Operations signatureParams(String[] args) {
        if (args == null || args.length < 1) {
            System.err.println("[ERRO] Nenhum argumento fornecido. Use SIGN ou VALIDATE como primeiro argumento.");
            System.exit(2);
        }

        String operationInput = args[0].toUpperCase();
        try {
            Operations op = Operations.valueOf(operationInput);
            if (op == Operations.INVALID) {
                System.err.println("[ERRO] Operação inválida: '" + operationInput + "'. Operações permitidas: SIGN, VALIDATE.");
                System.exit(2);
            }
            return op;
        } catch (IllegalArgumentException e) {
            System.err.println("[ERRO] Operação desconhecida: '" + operationInput + "'. Operações permitidas: SIGN, VALIDATE.");
            System.exit(2);
            return Operations.INVALID; // nunca alcançado
        }
    }

    // -------------------------------------------------------------------------
    // SIGN
    // -------------------------------------------------------------------------

    /**
     * Valida todos os parâmetros necessários para a operação SIGN.
     * Retorna true apenas se todos os parâmetros estiverem presentes e válidos.
     * Em caso de erro, imprime mensagem descritiva em stderr e retorna false.
     */
    public boolean createSignatureParams(String[] args) {
        ValidationResult result = validateSign(args);
        if (!result.isValid()) {
            System.err.println("[ERRO] " + result.getMessage());
            System.err.println("[DICA] Como corrigir: " + result.getHint());
            return false;
        }
        return true;
    }

    private ValidationResult validateSign(String[] args) {
        if (args.length < 8) {
            return ValidationResult.fail(
                "Parâmetros insuficientes para SIGN. Esperado: 8, recebido: " + args.length + ".",
                "Forneça: SIGN <bundle> <provenance> <config-cripto-json> <cert> <timestamp> <estrategia> <pid>"
            );
        }

        // args[1] — bundle
        ValidationResult bundle = requireReadableFile(args[1], "bundle (args[1])");
        if (!bundle.isValid()) return bundle;

        // args[2] — provenance
        ValidationResult provenance = requireReadableFile(args[2], "provenance (args[2])");
        if (!provenance.isValid()) return provenance;

        // args[3] — config-cripto JSON (string, não arquivo)
        if (isBlank(args[3])) {
            return ValidationResult.fail(
                "Parâmetro 'config-cripto-json' (args[3]) está vazio.",
                "Forneça um JSON válido com chave PKCS12 ou TOKEN/SMARTCARD."
            );
        }
        if (!args[3].trim().startsWith("{")) {
            return ValidationResult.fail(
                "Parâmetro 'config-cripto-json' (args[3]) não parece ser um JSON: '" + truncate(args[3]) + "'.",
                "O valor deve ser um objeto JSON começando com '{'. Exemplos: {\"PKCS12\":{...}} ou {\"TOKEN\":{...}}"
            );
        }

        // args[4] — certificado
        ValidationResult cert = requireReadableFile(args[4], "certificado (args[4])");
        if (!cert.isValid()) return cert;

        // args[5] — timestamp
        if (isBlank(args[5])) {
            return ValidationResult.fail(
                "Parâmetro 'timestamp' (args[5]) está vazio.",
                "Forneça um timestamp Unix em segundos (ex.: 1751328000)."
            );
        }
        try {
            long ts = Long.parseLong(args[5].trim());
            if (ts <= 0) {
                return ValidationResult.fail(
                    "Parâmetro 'timestamp' (args[5]) deve ser positivo, recebido: " + ts + ".",
                    "Use um timestamp Unix em segundos, ex.: " + (System.currentTimeMillis() / 1000) + "."
                );
            }
        } catch (NumberFormatException e) {
            return ValidationResult.fail(
                "Parâmetro 'timestamp' (args[5]) não é um número inteiro válido: '" + args[5] + "'.",
                "Forneça um timestamp Unix em segundos (ex.: 1751328000)."
            );
        }

        // args[6] — estratégia
        if (isBlank(args[6])) {
            return ValidationResult.fail(
                "Parâmetro 'estrategia' (args[6]) está vazio.",
                "Forneça uma estratégia de assinatura (ex.: 'AD_RB' ou 'AD_RT')."
            );
        }

        // args[7] — pid
        if (isBlank(args[7])) {
            return ValidationResult.fail(
                "Parâmetro 'pid' (args[7]) está vazio.",
                "Forneça o identificador do assinante (PID)."
            );
        }

        return ValidationResult.ok();
    }

    // -------------------------------------------------------------------------
    // VALIDATE
    // -------------------------------------------------------------------------

    /**
     * Valida os parâmetros necessários para a operação VALIDATE.
     */
    public boolean validateSignatureParams(String[] args) {
        ValidationResult result = validateValidate(args);
        if (!result.isValid()) {
            System.err.println("[ERRO] " + result.getMessage());
            System.err.println("[DICA] Como corrigir: " + result.getHint());
            return false;
        }
        return true;
    }

    private ValidationResult validateValidate(String[] args) {
        if (args.length < 3) {
            return ValidationResult.fail(
                "Parâmetros insuficientes para VALIDATE. Esperado: 3, recebido: " + args.length + ".",
                "Forneça: VALIDATE <jws-ou-operation-outcome> <config-json>"
            );
        }

        // args[1] — JWS ou OperationOutcome JSON
        if (isBlank(args[1])) {
            return ValidationResult.fail(
                "Parâmetro 'jws' (args[1]) está vazio.",
                "Forneça o JWS compacto (ex.: eyJ...) ou um JSON OperationOutcome contendo o JWS em 'diagnostics'."
            );
        }

        String jws = args[1].trim();
        boolean isCompact = jws.contains(".") && !jws.startsWith("{");
        boolean isJson = jws.startsWith("{");
        if (!isCompact && !isJson) {
            return ValidationResult.fail(
                "Parâmetro 'jws' (args[1]) não é um JWS compacto nem um JSON: '" + truncate(jws) + "'.",
                "Forneça um JWS no formato 'header.payload.signature' ou um JSON OperationOutcome."
            );
        }

        // args[2] — config JSON
        if (isBlank(args[2])) {
            return ValidationResult.fail(
                "Parâmetro 'config-json' (args[2]) está vazio.",
                "Forneça um JSON de configuração com ao menos {\"trustStore\":[\"<sha256-da-ac-raiz>\"]}."
            );
        }
        if (!args[2].trim().startsWith("{")) {
            return ValidationResult.fail(
                "Parâmetro 'config-json' (args[2]) não parece ser um JSON: '" + truncate(args[2]) + "'.",
                "O valor deve ser um objeto JSON começando com '{'."
            );
        }

        return ValidationResult.ok();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private ValidationResult requireReadableFile(String path, String label) {
        if (isBlank(path)) {
            return ValidationResult.fail(
                "Parâmetro '" + label + "' está vazio.",
                "Forneça o caminho para um arquivo legível."
            );
        }
        Path p = Paths.get(path.trim());
        if (!Files.exists(p)) {
            return ValidationResult.fail(
                "Arquivo '" + label + "' não encontrado: '" + path + "'.",
                "Verifique se o caminho está correto e o arquivo existe."
            );
        }
        if (!Files.isReadable(p)) {
            return ValidationResult.fail(
                "Arquivo '" + label + "' não tem permissão de leitura: '" + path + "'.",
                "Verifique as permissões do arquivo (ex.: chmod 644 " + path + ")."
            );
        }
        return ValidationResult.ok();
    }

    private boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private String truncate(String s) {
        return s.length() > 60 ? s.substring(0, 60) + "..." : s;
    }
}
