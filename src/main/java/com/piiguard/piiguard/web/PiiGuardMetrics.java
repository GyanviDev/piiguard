package com.piiguard.piiguard.web;

import com.piiguard.piiguard.privacy.PiiEntityType;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Instrumentation for the things that would otherwise fail silently.
 *
 * <p>The project had no telemetry at all, which meant an entire class of failure was
 * invisible: the proxy can stop redacting anything and still return 200 OK to every caller.
 * Nothing about a successful response tells you whether the sanitiser found the card number or
 * missed it. Uptime graphs and error rates look perfect while the product does nothing.
 *
 * <p>The metrics chosen here are the ones a privacy control needs rather than the ones a web
 * service needs. In particular {@code piiguard.pii.redacted} suddenly dropping to zero, or
 * {@code piiguard.output.generated_pii} rising, are the alerts that catch a broken deployment
 * — and neither is derivable from request counts and latencies.
 *
 * <p>Deliberately absent: any tag carrying prompt content, a session id, or a redacted value.
 * Metric labels are stored indefinitely in systems with far weaker access control than the
 * application, and unbounded label values are also the classic way to bring down Prometheus.
 */
@Component
public class PiiGuardMetrics {

    private final MeterRegistry registry;
    private final Counter promptsProcessed;
    private final Counter attacksBlocked;
    private final Counter llmFailures;
    private final Counter budgetExhausted;
    private final Counter vaultCapacityHits;
    private final Counter unknownTokensInOutput;
    private final Counter generatedPiiInOutput;
    private final Timer requestTimer;
    private final Map<PiiEntityType, Counter> redactionCounters = new ConcurrentHashMap<>();

    public PiiGuardMetrics(MeterRegistry registry) {
        this.registry = registry;
        this.promptsProcessed = Counter.builder("piiguard.prompts.processed")
                .description("Prompts that completed the full pipeline").register(registry);
        this.attacksBlocked = Counter.builder("piiguard.attacks.blocked")
                .description("Prompts refused by the threat detector").register(registry);
        this.llmFailures = Counter.builder("piiguard.llm.failures")
                .description("Upstream model calls that did not return a completion").register(registry);
        this.budgetExhausted = Counter.builder("piiguard.dp.budget_exhausted")
                .description("Requests that skipped noising because the privacy budget was spent")
                .register(registry);
        this.vaultCapacityHits = Counter.builder("piiguard.vault.capacity_exceeded")
                .description("Redactions that fell back to irreversible markers").register(registry);
        this.unknownTokensInOutput = Counter.builder("piiguard.output.unknown_tokens")
                .description("Placeholder-shaped strings in model output that this session never issued")
                .register(registry);
        this.generatedPiiInOutput = Counter.builder("piiguard.output.generated_pii")
                .description("Model responses containing sensitive-looking values the model invented")
                .register(registry);
        this.requestTimer = Timer.builder("piiguard.request.duration")
                .description("End-to-end proxy latency").register(registry);
    }

    public void promptProcessed() { promptsProcessed.increment(); }
    public void attackBlocked(String method) {
        attacksBlocked.increment();
        // Method is a small, closed set, so it is safe as a tag; a rule name would be too.
        registry.counter("piiguard.attacks.blocked.by_method", "method", method).increment();
    }
    public void llmFailure() { llmFailures.increment(); }
    public void budgetExhausted() { budgetExhausted.increment(); }
    public void vaultCapacityExceeded() { vaultCapacityHits.increment(); }
    public void unknownTokens(int count) { unknownTokensInOutput.increment(count); }
    public void generatedPii() { generatedPiiInOutput.increment(); }

    public void redacted(Map<PiiEntityType, Integer> counts) {
        counts.forEach((type, count) -> redactionCounters
                .computeIfAbsent(type, t -> Counter.builder("piiguard.pii.redacted")
                        .tag("type", t.name())
                        .description("Sensitive values replaced with placeholders")
                        .register(registry))
                .increment(count));
    }

    public Timer requestTimer() {
        return requestTimer;
    }
}
