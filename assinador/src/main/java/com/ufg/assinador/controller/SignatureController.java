package com.ufg.assinador.controller;

import com.ufg.assinador.dto.SignRequest;
import com.ufg.assinador.dto.ValidateRequest;
import com.ufg.assinador.services.SignatureService;
import com.ufg.assinador.validations.SignatureParamsValidation;
import com.ufg.assinador.validations.ValidationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Controlador REST do assinador no modo servidor.
 *
 * Endpoints:
 *   GET  /health         — health check (readiness: servidor pronto para receber requisições)
 *   POST /sign           — cria assinatura digital
 *   POST /validate       — valida assinatura digital
 *   POST /shutdown       — encerra o servidor de forma controlada
 *
 * Auto-shutdown:
 *   Se a variável de ambiente ASSINADOR_TIMEOUT_MINUTOS estiver definida (inteiro > 0),
 *   o servidor se encerra automaticamente após esse período sem receber requisições.
 *   O timer é reiniciado a cada requisição recebida nos endpoints /sign e /validate.
 */
@RestController
public class SignatureController {

    @Autowired
    private SignatureService signatureService;

    @Autowired
    private SignatureParamsValidation paramsValidation;

    @Autowired
    private ApplicationContext applicationContext;

    /** Timestamp da última requisição recebida (epoch seconds). */
    private final AtomicLong lastActivityAt = new AtomicLong(Instant.now().getEpochSecond());

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final AtomicReference<ScheduledFuture<?>> shutdownTask = new AtomicReference<>();

    // Inicializa o timer de auto-shutdown ao criar o bean
    public SignatureController() {
        scheduleAutoShutdown();
    }

    // -------------------------------------------------------------------------
    // Health check
    // -------------------------------------------------------------------------

    /**
     * Retorna 200 OK quando o servidor está pronto para receber requisições.
     * Usado pelo CLI para distinguir "porta ocupada" de "servidor pronto".
     */
    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("{\"status\":\"UP\",\"service\":\"assinador\"}");
    }

    // -------------------------------------------------------------------------
    // POST /sign
    // -------------------------------------------------------------------------

    @PostMapping(
        value = "/sign",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> sign(@RequestBody SignRequest req) {
        resetActivityTimer();

        if (req == null) {
            return badRequest("Corpo da requisição ausente. Envie um JSON com os campos: bundle, provenance, configCripto, cert, timestamp, estrategia, pid.");
        }

        // Monta array de args no mesmo contrato do modo CLI
        String[] args = {
            "SIGN",
            nullToEmpty(req.bundle),
            nullToEmpty(req.provenance),
            nullToEmpty(req.configCripto),
            nullToEmpty(req.cert),
            nullToEmpty(req.timestamp),
            nullToEmpty(req.estrategia),
            nullToEmpty(req.pid)
        };

        if (!paramsValidation.createSignatureParams(args)) {
            return badRequest("Parâmetros inválidos para SIGN. Verifique os campos obrigatórios: bundle, provenance, configCripto, cert, timestamp, estrategia, pid.");
        }

        String result = signatureService.generateSignature(args);
        return outcomeResponse(result);
    }

    // -------------------------------------------------------------------------
    // POST /validate
    // -------------------------------------------------------------------------

    @PostMapping(
        value = "/validate",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> validate(@RequestBody ValidateRequest req) {
        resetActivityTimer();

        if (req == null) {
            return badRequest("Corpo da requisição ausente. Envie um JSON com os campos: jws, configJson.");
        }

        String[] args = {
            "VALIDATE",
            nullToEmpty(req.jws),
            nullToEmpty(req.configJson)
        };

        if (!paramsValidation.validateSignatureParams(args)) {
            return badRequest("Parâmetros inválidos para VALIDATE. Verifique os campos obrigatórios: jws, configJson.");
        }

        String result = signatureService.validate(args);
        return outcomeResponse(result);
    }

    // -------------------------------------------------------------------------
    // POST /shutdown
    // -------------------------------------------------------------------------

    /**
     * Encerra o servidor de forma controlada.
     * Retorna 200 antes de iniciar o shutdown para que o cliente receba a resposta.
     */
    @PostMapping(value = "/shutdown", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> shutdown() {
        scheduler.schedule(() -> {
            System.out.println("[assinador] Recebido comando de shutdown. Encerrando...");
            System.exit(0);
        }, 200, TimeUnit.MILLISECONDS);

        return ResponseEntity.ok("{\"status\":\"SHUTTING_DOWN\"}");
    }

    // -------------------------------------------------------------------------
    // Auto-shutdown por inatividade
    // -------------------------------------------------------------------------

    private void scheduleAutoShutdown() {
        String envTimeout = System.getenv("ASSINADOR_TIMEOUT_MINUTOS");
        if (envTimeout == null || envTimeout.isBlank()) return;

        int minutos;
        try {
            minutos = Integer.parseInt(envTimeout.trim());
        } catch (NumberFormatException e) {
            System.err.println("[assinador] ASSINADOR_TIMEOUT_MINUTOS inválido: '" + envTimeout + "'. Auto-shutdown desativado.");
            return;
        }

        if (minutos <= 0) return;

        System.out.printf("[assinador] Auto-shutdown ativado: %d minuto(s) de inatividade.%n", minutos);
        rescheduleShutdown(minutos);
    }

    private void resetActivityTimer() {
        lastActivityAt.set(Instant.now().getEpochSecond());

        String envTimeout = System.getenv("ASSINADOR_TIMEOUT_MINUTOS");
        if (envTimeout == null || envTimeout.isBlank()) return;

        try {
            int minutos = Integer.parseInt(envTimeout.trim());
            if (minutos > 0) rescheduleShutdown(minutos);
        } catch (NumberFormatException ignored) {}
    }

    private void rescheduleShutdown(int minutos) {
        ScheduledFuture<?> existing = shutdownTask.get();
        if (existing != null) existing.cancel(false);

        ScheduledFuture<?> next = scheduler.schedule(() -> {
            long idleSeconds = Instant.now().getEpochSecond() - lastActivityAt.get();
            System.out.printf("[assinador] Inatividade de %ds >= %ds. Encerrando por timeout.%n",
                idleSeconds, minutos * 60L);
            System.exit(0);
        }, minutos, TimeUnit.MINUTES);

        shutdownTask.set(next);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Retorna 200 para OperationOutcome de sucesso, 422 para fatal.
     * Isso permite que o CLI distinga erros de negócio de erros HTTP.
     */
    private ResponseEntity<String> outcomeResponse(String outcome) {
        if (outcome != null && outcome.contains("\"fatal\"")) {
            return ResponseEntity.unprocessableEntity().body(outcome);
        }
        return ResponseEntity.ok(outcome);
    }

    private ResponseEntity<String> badRequest(String message) {
        String body = String.format(
            "{\"resourceType\":\"OperationOutcome\",\"issue\":[{\"severity\":\"error\",\"code\":\"invalid\",\"details\":{\"text\":\"%s\"}}]}",
            message.replace("\"", "'")
        );
        return ResponseEntity.badRequest().body(body);
    }

    private String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
