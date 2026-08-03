package com.piiguard.piiguard.web;

import com.piiguard.piiguard.llm.LlmClient;
import com.piiguard.piiguard.privacy.TokenVault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Turns exceptions into responses, on purpose rather than by default.
 *
 * <p>With no handler, Spring's fallback error page answers a malformed request with the
 * exception type, message and — depending on configuration — a stack trace. In this
 * application that is a live disclosure risk rather than a theoretical one: a
 * {@code HttpMessageNotReadableException} from a truncated JSON body quotes <em>the body it
 * failed to parse</em>, which is the user's unredacted prompt. The proxy would leak the exact
 * data it exists to protect, through its own error path, to whoever malformed the request.
 *
 * <p>So the rule here is: the caller learns what to do differently, and nothing else. Detail
 * goes to the log behind a correlation id the user can quote in a support request.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** Field-level validation failures. Safe to return: they describe our contract, not their data. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> onValidationError(MethodArgumentNotValidException e) {
        String detail = e.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));
        return problem(HttpStatus.BAD_REQUEST, detail.isBlank() ? "Invalid request" : detail, null);
    }

    /**
     * Deliberately does not echo the parse error. Jackson's message includes a snippet of the
     * offending payload, and that payload is a prompt.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> onUnreadableBody(HttpMessageNotReadableException e) {
        String reference = reference();
        log.warn("[{}] Malformed request body: {}", reference, e.getClass().getSimpleName());
        return problem(HttpStatus.BAD_REQUEST, "Request body is not valid JSON", reference);
    }

    @ExceptionHandler(LlmClient.LlmUnavailableException.class)
    public ResponseEntity<Map<String, Object>> onLlmUnavailable(LlmClient.LlmUnavailableException e) {
        return problem(HttpStatus.BAD_GATEWAY, e.getMessage(), null);
    }

    @ExceptionHandler(TokenVault.VaultCapacityException.class)
    public ResponseEntity<Map<String, Object>> onVaultFull(TokenVault.VaultCapacityException e) {
        String reference = reference();
        log.warn("[{}] Vault capacity: {}", reference, e.getMessage());
        return problem(HttpStatus.SERVICE_UNAVAILABLE,
                "The proxy is at capacity. Please retry shortly.", reference);
    }

    /**
     * The catch-all. Logs the full stack trace for the operator and returns a fixed string,
     * because at this point the exception is by definition one nobody anticipated, and an
     * unanticipated exception's message is not something to hand to an untrusted caller.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> onUnexpected(Exception e) {
        String reference = reference();
        log.error("[{}] Unhandled exception", reference, e);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred.", reference);
    }

    private static String reference() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private static ResponseEntity<Map<String, Object>> problem(HttpStatus status, String message, String reference) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", message);
        body.put("status", status.name());
        body.put("timestamp", Instant.now().toString());
        if (reference != null) {
            body.put("reference", reference);
        }
        return ResponseEntity.status(status).body(body);
    }
}
