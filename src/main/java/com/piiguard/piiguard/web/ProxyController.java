package com.piiguard.piiguard.web;

import com.piiguard.piiguard.audit.AuditLog;
import com.piiguard.piiguard.audit.AuditService;
import com.piiguard.piiguard.config.PiiGuardProperties;
import com.piiguard.piiguard.detect.AdversarialHarnessService;
import com.piiguard.piiguard.detect.MlDetectionService;
import com.piiguard.piiguard.detect.ThreatVerdict;
import com.piiguard.piiguard.llm.LlmClient;
import com.piiguard.piiguard.privacy.DifferentialPrivacyService;
import com.piiguard.piiguard.privacy.NerService;
import com.piiguard.piiguard.privacy.OutputGuard;
import com.piiguard.piiguard.privacy.PrivacyBudgetAccountant;
import com.piiguard.piiguard.privacy.SanitizationPipeline;
import com.piiguard.piiguard.privacy.TokenVault;
import com.piiguard.piiguard.web.dto.ProxyRequest;
import com.piiguard.piiguard.web.dto.ProxyResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The public surface of the proxy.
 *
 * <p>The controller's job is orchestration and HTTP semantics — nothing else. The original one
 * did tokenisation, name detection, noise application, the outbound HTTP call, response parsing
 * and token re-injection inline, in a single 55-line method with a private regex helper at the
 * bottom. Everything it did is now behind a collaborator that can be unit-tested without a
 * servlet container, which is the difference between "the tests pass" and "the redaction logic
 * is tested".
 *
 * <h3>The ordering of the pipeline, and why it is what it is</h3>
 * <ol>
 *   <li><b>Threat check before anything else.</b> An attack prompt is refused before it can
 *       consume vault capacity, model spend or privacy budget. Rejecting expensive work early
 *       is the whole point of putting the cheapest check first.</li>
 *   <li><b>Redact before noise.</b> Reversed, the noise stage would rewrite digits inside
 *       values the redactor had not yet claimed, changing a card number just enough to fail
 *       its Luhn check and be forwarded in the clear.</li>
 *   <li><b>Noise before transmission, restoration after.</b> Obvious, and worth stating because
 *       it is the invariant the whole design rests on: the network call sits between the two,
 *       and nothing real crosses it.</li>
 * </ol>
 */
@RestController
@RequestMapping("/api")
public class ProxyController {

    private final SanitizationPipeline sanitizer;
    private final DifferentialPrivacyService dpService;
    private final PrivacyBudgetAccountant budgetAccountant;
    private final AdversarialHarnessService threatDetector;
    private final MlDetectionService mlDetection;
    private final NerService nerService;
    private final LlmClient llmClient;
    private final OutputGuard outputGuard;
    private final TokenVault vault;
    private final AuditService auditService;
    private final PiiGuardMetrics metrics;
    private final PiiGuardProperties properties;

    public ProxyController(SanitizationPipeline sanitizer,
                           DifferentialPrivacyService dpService,
                           PrivacyBudgetAccountant budgetAccountant,
                           AdversarialHarnessService threatDetector,
                           MlDetectionService mlDetection,
                           NerService nerService,
                           LlmClient llmClient,
                           OutputGuard outputGuard,
                           TokenVault vault,
                           AuditService auditService,
                           PiiGuardMetrics metrics,
                           PiiGuardProperties properties) {
        this.sanitizer = sanitizer;
        this.dpService = dpService;
        this.budgetAccountant = budgetAccountant;
        this.threatDetector = threatDetector;
        this.mlDetection = mlDetection;
        this.nerService = nerService;
        this.llmClient = llmClient;
        this.outputGuard = outputGuard;
        this.vault = vault;
        this.auditService = auditService;
        this.metrics = metrics;
        this.properties = properties;
    }

    @PostMapping("/proxy")
    public ResponseEntity<ProxyResponse> proxy(@Valid @RequestBody ProxyRequest request,
                                               HttpServletRequest httpRequest) {

        String sessionId = UUID.randomUUID().toString();
        String prompt = request.prompt();
        long startedAt = System.nanoTime();

        // The single most important line in this class. The original called clearSession()
        // only on the success path, so any exception between tokenisation and cleanup — a
        // timeout talking to the model was enough — stranded the user's plaintext PII in a
        // process-lifetime map. A privacy guarantee that holds only when nothing goes wrong is
        // not a guarantee; try/finally is what makes destruction unconditional.
        try {
            return handle(request, prompt, sessionId, httpRequest, startedAt);
        } finally {
            vault.clearSession(sessionId);
        }
    }

    private ResponseEntity<ProxyResponse> handle(ProxyRequest request,
                                                 String prompt,
                                                 String sessionId,
                                                 HttpServletRequest httpRequest,
                                                 long startedAt) {

        // ── 1. Threat detection ───────────────────────────────────────────────────
        ThreatVerdict verdict = threatDetector.evaluate(prompt);

        if (verdict.attack()) {
            metrics.attackBlocked(verdict.method());
            auditService.record(AuditLog.builder()
                    .sessionId(sessionId)
                    .redactedPrompt(null)
                    .attackDetected(true)
                    .detectionMethod(verdict.method())
                    .detectionRule(verdict.rule())
                    .detectionConfidence(verdict.confidence())
                    .outcome("BLOCKED")
                    .latencyMillis(elapsedMillis(startedAt)), prompt);

            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ProxyResponse(
                    null,
                    "Request blocked: the prompt matched an adversarial pattern.",
                    sessionId,
                    true,
                    verdict.method(),
                    verdict.rule(),
                    Map.of(),
                    0,
                    List.of()));
        }

        // ── 2. Redaction ──────────────────────────────────────────────────────────
        SanitizationPipeline.SanitizationResult sanitized = sanitizer.sanitize(prompt, sessionId);
        metrics.redacted(sanitized.countsByType());
        if (sanitized.truncated()) {
            metrics.vaultCapacityExceeded();
        }

        List<String> warnings = new ArrayList<>();
        if (sanitized.truncated()) {
            warnings.add("Too many distinct sensitive values; some were redacted irreversibly "
                       + "and will not be restored in the response.");
        }

        // ── 3. Numeric perturbation, subject to the privacy budget ────────────────
        String subject = budgetSubject(httpRequest);
        String outbound = sanitized.sanitizedText();
        int valuesNoised = 0;

        if (request.noiseRequested() && dpService.isEnabled()) {
            if (budgetAccountant.check(subject).allowed()) {
                DifferentialPrivacyService.DpResult dp = dpService.apply(outbound);
                outbound = dp.text();
                valuesNoised = dp.valuesNoised();
                budgetAccountant.charge(subject, dp.epsilonSpent());
            } else {
                metrics.budgetExhausted();
                warnings.add("Privacy budget exhausted for this caller; numeric values were "
                           + "sent without perturbation.");
            }
        }

        // ── 4. Upstream call ──────────────────────────────────────────────────────
        String modelOutput;
        try {
            modelOutput = llmClient.complete(outbound);
        } catch (LlmClient.LlmUnavailableException e) {
            metrics.llmFailure();
            auditService.record(AuditLog.builder()
                    .sessionId(sessionId)
                    .redactedPrompt(outbound)
                    .piiSummary(AuditService.summarise(sanitized.countsByType()))
                    .detectionMethod(verdict.method())
                    .detectionRule(verdict.rule())
                    .outcome("LLM_UNAVAILABLE")
                    .dpValuesNoised(valuesNoised)
                    .latencyMillis(elapsedMillis(startedAt)), prompt);

            // 502, not 200 with an error string in the answer field. A caller must be able to
            // tell "the model said this" from "the model could not be reached".
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(new ProxyResponse(
                    outbound, e.getMessage(), sessionId, false,
                    verdict.method(), verdict.rule(),
                    sanitized.countsByType(), valuesNoised, warnings));
        }

        // ── 5. Outbound inspection and restoration ────────────────────────────────
        OutputGuard.GuardedResponse guarded = outputGuard.process(modelOutput, sessionId, vault);

        if (!guarded.unknownTokens().isEmpty()) {
            metrics.unknownTokens(guarded.unknownTokens().size());
            warnings.add("The response contained " + guarded.unknownTokens().size()
                       + " placeholder(s) this session never issued; they were left unresolved.");
        }
        if (!guarded.generatedPiiTypes().isEmpty()) {
            metrics.generatedPii();
            warnings.add("The model generated text resembling "
                       + guarded.generatedPiiTypes() + ". These values were invented by the "
                       + "model and are not from your prompt.");
        }

        metrics.promptProcessed();
        metrics.requestTimer().record(java.time.Duration.ofMillis(elapsedMillis(startedAt)));

        auditService.record(AuditLog.builder()
                .sessionId(sessionId)
                .redactedPrompt(outbound)
                .piiSummary(AuditService.summarise(sanitized.countsByType()))
                .detectionMethod(verdict.method())
                .detectionRule(verdict.rule())
                .outcome("OK")
                .dpValuesNoised(valuesNoised)
                .latencyMillis(elapsedMillis(startedAt)), prompt);

        return ResponseEntity.ok(new ProxyResponse(
                outbound,
                guarded.text(),
                sessionId,
                false,
                verdict.method(),
                verdict.rule(),
                sanitized.countsByType(),
                valuesNoised,
                warnings));
    }

    /**
     * Liveness and configuration state. Public, so it deliberately reports only booleans —
     * enough for an operator or an uptime check to see that the proxy is degraded, and not
     * enough to tell an attacker which specific defence is currently off.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "UP");
        body.put("nerModelLoaded", nerService.isLoaded());
        body.put("mlServiceAvailable", mlDetection.isServiceAvailable());
        body.put("llmConfigured", llmClient.isConfigured());
        // Whether an admin key was configured at boot — never the key itself, and never
        // whether a particular key was correct. Without this, "my key is rejected" and
        // "the environment variable never reached the container" are indistinguishable
        // from outside, and the only way to tell them apart is to keep guessing. It
        // discloses nothing exploitable: a caller who learns admin auth is unconfigured
        // learns only that the endpoints they already cannot reach are switched off.
        body.put("adminAuthConfigured", !properties.getAdminApiKey().isBlank());
        return ResponseEntity.ok(body);
    }

    /**
     * The privacy budget is charged per caller, so the key must identify the caller rather
     * than the request. Sessions are single-request here, so keying on session would have made
     * the budget unspendable and the accountant decorative.
     */
    private String budgetSubject(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
        }
        return request.getRemoteAddr();
    }

    private long elapsedMillis(long startedAtNanos) {
        return (System.nanoTime() - startedAtNanos) / 1_000_000L;
    }
}
