package com.piiguard.piiguard.detect;

import com.piiguard.piiguard.config.PiiGuardProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Client for the Python attack classifier, with the failure handling a network dependency needs.
 *
 * <h3>What was wrong</h3>
 *
 * <p><b>No timeouts.</b> The service constructed a bare {@code RestTemplate}, which waits
 * forever. A hung sidecar would hold every Tomcat worker thread that touched it until the pool
 * was exhausted and the proxy stopped answering anything at all — an outage in a dependency
 * turning into an outage in the product. Timeouts now come from configuration.
 *
 * <p><b>Every failure became "SAFE".</b> {@code catch (Exception e)} returning a safe verdict
 * means a service that is down, misconfigured, slow, or returning malformed JSON is
 * indistinguishable from a service that examined the prompt and approved it. The distinction
 * is now explicit — an empty {@link Optional} means "no opinion", and the caller decides what
 * that is worth. Deployments that must not fail open can set
 * {@code piiguard.detection.fail-closed=true}.
 *
 * <p><b>It kept calling a dead service.</b> With a 3-second timeout and a sidecar that is down,
 * every request pays 3 seconds to learn what the previous request already established. The
 * circuit breaker below stops calling after a threshold of consecutive failures and lets a
 * single probe through after a cooldown. Its real purpose is not our latency — it is not
 * hammering a service that is struggling and may be trying to recover.
 */
@Component
public class MlDetectionService {

    private static final Logger log = LoggerFactory.getLogger(MlDetectionService.class);

    private final RestTemplate restTemplate;
    private final PiiGuardProperties.Detection config;

    private final AtomicInteger consecutiveFailures = new AtomicInteger();
    private final AtomicLong circuitOpenedAt = new AtomicLong();

    /** Health is polled on a schedule rather than probed inline — see {@link #refreshHealth()}. */
    private volatile boolean serviceHealthy = false;

    public MlDetectionService(@Qualifier("mlRestTemplate") RestTemplate restTemplate,
                              PiiGuardProperties props) {
        this.restTemplate = restTemplate;
        this.config = props.getDetection();
    }

    /** @param label {@code ATTACK} or {@code SAFE}; @param confidence the model's probability */
    public record MlPrediction(String label, double confidence) {
        public boolean isAttack() {
            return "ATTACK".equals(label);
        }
    }

    /**
     * @return the model's opinion, or empty when the classifier could not be consulted —
     *         a state the caller must handle deliberately rather than read as approval
     */
    public Optional<MlPrediction> classify(String prompt) {
        if (isCircuitOpen()) {
            return Optional.empty();
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            if (!config.getMlApiKey().isBlank()) {
                headers.set("X-API-Key", config.getMlApiKey());
            }

            HttpEntity<Map<String, String>> entity = new HttpEntity<>(Map.of("prompt", prompt), headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(
                    config.getMlServiceUrl() + "/predict", entity, Map.class);

            Map<?, ?> body = response.getBody();
            if (body == null) {
                return recordFailure("empty response body");
            }

            Object label = body.get("label");
            Object confidence = body.get("confidence");
            if (!(label instanceof String labelText) || !(confidence instanceof Number confidenceValue)) {
                return recordFailure("unexpected response shape");
            }

            consecutiveFailures.set(0);
            serviceHealthy = true;
            return Optional.of(new MlPrediction(labelText, confidenceValue.doubleValue()));

        } catch (Exception e) {
            return recordFailure(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private Optional<MlPrediction> recordFailure(String reason) {
        int failures = consecutiveFailures.incrementAndGet();
        serviceHealthy = false;

        if (failures == config.getCircuitBreakerThreshold()) {
            circuitOpenedAt.set(System.currentTimeMillis());
            log.warn("ML classifier circuit OPEN after {} consecutive failures: {}", failures, reason);
        } else if (failures < config.getCircuitBreakerThreshold()) {
            log.debug("ML classifier call failed ({}/{}): {}",
                    failures, config.getCircuitBreakerThreshold(), reason);
        }
        return Optional.empty();
    }

    private boolean isCircuitOpen() {
        if (consecutiveFailures.get() < config.getCircuitBreakerThreshold()) {
            return false;
        }
        long elapsed = System.currentTimeMillis() - circuitOpenedAt.get();
        if (elapsed >= config.getCircuitBreakerResetTimeout().toMillis()) {
            // Half-open: allow one probe. If it succeeds the counter resets in classify().
            consecutiveFailures.set(config.getCircuitBreakerThreshold() - 1);
            log.info("ML classifier circuit HALF-OPEN — allowing a probe request");
            return false;
        }
        return true;
    }

    /**
     * The old {@code isServiceAvailable()} performed a live HTTP call and was invoked from
     * {@code /api/proxy}, {@code /api/health} and {@code /api/status} — so reporting status
     * cost a network round trip, and a health check on a dead sidecar blocked for the full
     * timeout. Polling on a schedule and serving a cached flag makes status reads free.
     */
    @org.springframework.scheduling.annotation.Scheduled(fixedDelay = 15_000L, initialDelay = 2_000L)
    public void refreshHealth() {
        try {
            ResponseEntity<Map> response = restTemplate.getForEntity(
                    config.getMlServiceUrl() + "/health", Map.class);
            serviceHealthy = response.getStatusCode().is2xxSuccessful();
            if (serviceHealthy) {
                consecutiveFailures.set(0);
            }
        } catch (Exception e) {
            serviceHealthy = false;
        }
    }

    public boolean isServiceAvailable() {
        return serviceHealthy;
    }

    public boolean isFailClosed() {
        return config.isFailClosed();
    }

    public double confidenceThreshold() {
        return config.getMlConfidenceThreshold();
    }
}
