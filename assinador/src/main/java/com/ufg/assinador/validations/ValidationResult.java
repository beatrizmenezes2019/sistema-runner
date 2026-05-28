package com.ufg.assinador.validations;

/**
 * Resultado imutável de uma validação de parâmetros.
 * Carrega a mensagem de erro e uma dica de correção para facilitar o diagnóstico pelo usuário.
 */
public final class ValidationResult {

    private final boolean valid;
    private final String message;
    private final String hint;

    private ValidationResult(boolean valid, String message, String hint) {
        this.valid = valid;
        this.message = message;
        this.hint = hint;
    }

    public static ValidationResult ok() {
        return new ValidationResult(true, "", "");
    }

    public static ValidationResult fail(String message, String hint) {
        return new ValidationResult(false, message, hint);
    }

    public boolean isValid() { return valid; }
    public String getMessage() { return message; }
    public String getHint() { return hint; }
}
