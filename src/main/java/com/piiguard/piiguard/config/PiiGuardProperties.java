package com.piiguard.piiguard.config;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Every tunable in one typed, validated place.
 *
 * <p>Previously these values were scattered as magic numbers across the codebase
 * ({@code EPSILON = 0.1} inside the DP service, {@code 10000} inline in the controller,
 * {@code "attackPatternsLoaded": 7} hard-coded in a JSON response that could silently
 * drift from reality). Binding them here means they are documented, validated at
 * startup, overridable per environment, and impossible to disagree with each other.
 */
@Validated
@ConfigurationProperties(prefix = "piiguard")
public class PiiGuardProperties {

    private final Vault vault = new Vault();
    private final Dp dp = new Dp();
    private final Detection detection = new Detection();
    private final Llm llm = new Llm();
    private final RateLimit rateLimit = new RateLimit();
    private final Audit audit = new Audit();

    /** Maximum accepted prompt length in characters. Enforced by Bean Validation on the DTO. */
    @Min(1)
    @Max(100_000)
    private int maxPromptLength = 10_000;

    /**
     * Shared secret required by admin endpoints ({@code /api/audit}, {@code /api/attack},
     * {@code /actuator/**}). Empty means admin endpoints are disabled entirely — a safe
     * default, because the previous behaviour was "wide open to the internet".
     */
    private String adminApiKey = "";

    public Vault getVault() { return vault; }
    public Dp getDp() { return dp; }
    public Detection getDetection() { return detection; }
    public Llm getLlm() { return llm; }
    public RateLimit getRateLimit() { return rateLimit; }
    public Audit getAudit() { return audit; }

    public int getMaxPromptLength() { return maxPromptLength; }
    public void setMaxPromptLength(int maxPromptLength) { this.maxPromptLength = maxPromptLength; }

    public String getAdminApiKey() { return adminApiKey; }
    public void setAdminApiKey(String adminApiKey) { this.adminApiKey = adminApiKey; }

    // ────────────────────────────────────────────────────────────────

    public static class Vault {
        /**
         * How long an abandoned session's secrets may live in memory before the sweeper
         * destroys them. The vault holds plaintext PII, so this is a hard privacy control,
         * not a performance knob.
         */
        private Duration ttl = Duration.ofMinutes(5);

        /** How often the eviction sweeper runs. */
        private Duration sweepInterval = Duration.ofMinutes(1);

        /** Cap on distinct PII values per session — bounds memory and blast radius. */
        @Min(1)
        private int maxEntriesPerSession = 500;

        /** Cap on concurrently tracked sessions — back-pressure instead of OutOfMemoryError. */
        @Min(1)
        private int maxSessions = 10_000;

        /**
         * Random characters in a token body. 12 letters from a 26-symbol alphabet is
         * ~56 bits; the old code used 4 hex characters (16 bits), which collides with
         * ~50% probability after roughly 300 tokens.
         */
        @Min(8)
        @Max(32)
        private int tokenLength = 12;

        public Duration getTtl() { return ttl; }
        public void setTtl(Duration ttl) { this.ttl = ttl; }
        public Duration getSweepInterval() { return sweepInterval; }
        public void setSweepInterval(Duration sweepInterval) { this.sweepInterval = sweepInterval; }
        public int getMaxEntriesPerSession() { return maxEntriesPerSession; }
        public void setMaxEntriesPerSession(int v) { this.maxEntriesPerSession = v; }
        public int getMaxSessions() { return maxSessions; }
        public void setMaxSessions(int v) { this.maxSessions = v; }
        public int getTokenLength() { return tokenLength; }
        public void setTokenLength(int tokenLength) { this.tokenLength = tokenLength; }
    }

    public static class Dp {
        /** Master switch. Numeric perturbation corrupts meaning, so it is opt-in per deployment. */
        private boolean enabled = true;

        /** Privacy budget per query. Lower epsilon = more noise = more privacy. */
        @Positive
        private double epsilon = 0.5;

        /**
         * Noise scale is {@code max(absoluteSensitivity, |value| * relativeSensitivity) / epsilon}.
         * Relative sensitivity is what makes this usable: a revenue figure of 4,500,000 gets
         * noise proportional to its magnitude instead of the ±10 the old fixed sensitivity gave it.
         */
        @Positive
        private double relativeSensitivity = 0.02;

        @Positive
        private double absoluteSensitivity = 1.0;

        /**
         * Numbers below this magnitude are left alone. Dosages, counts, ages and ratings
         * carry meaning that noise destroys ("take 2 tablets" must not become "take -7 tablets"),
         * and they are rarely the aggregate statistics DP is meant to protect.
         */
        @Min(0)
        private long minMagnitude = 1_000;

        /** Four-digit values in this range are treated as years and never perturbed. */
        private int yearFloor = 1900;
        private int yearCeiling = 2100;

        /** Total epsilon a single session may spend before further DP requests are refused. */
        @Positive
        private double sessionBudget = 5.0;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public double getEpsilon() { return epsilon; }
        public void setEpsilon(double epsilon) { this.epsilon = epsilon; }
        public double getRelativeSensitivity() { return relativeSensitivity; }
        public void setRelativeSensitivity(double v) { this.relativeSensitivity = v; }
        public double getAbsoluteSensitivity() { return absoluteSensitivity; }
        public void setAbsoluteSensitivity(double v) { this.absoluteSensitivity = v; }
        public long getMinMagnitude() { return minMagnitude; }
        public void setMinMagnitude(long v) { this.minMagnitude = v; }
        public int getYearFloor() { return yearFloor; }
        public void setYearFloor(int v) { this.yearFloor = v; }
        public int getYearCeiling() { return yearCeiling; }
        public void setYearCeiling(int v) { this.yearCeiling = v; }
        public double getSessionBudget() { return sessionBudget; }
        public void setSessionBudget(double v) { this.sessionBudget = v; }
    }

    public static class Detection {
        /** Base URL of the Python ML classifier. */
        private String mlServiceUrl = "http://localhost:8000";

        /** Optional shared secret sent as {@code X-API-Key} to the ML service. */
        private String mlApiKey = "";

        /** Minimum ML confidence required to block on the model's word alone. */
        @Min(0)
        @Max(1)
        private double mlConfidenceThreshold = 0.75;

        private Duration mlConnectTimeout = Duration.ofSeconds(2);
        private Duration mlReadTimeout = Duration.ofSeconds(3);

        /**
         * If true, an unreachable ML service causes requests to be rejected rather than
         * silently falling back to regex only. False (fail-open to the regex layer) keeps
         * the product usable; true is the correct choice for regulated deployments.
         */
        private boolean failClosed = false;

        /** Consecutive ML failures before the circuit opens and we stop calling it. */
        @Min(1)
        private int circuitBreakerThreshold = 3;

        /** How long the circuit stays open before a probe request is allowed through. */
        private Duration circuitBreakerResetTimeout = Duration.ofSeconds(30);

        public String getMlServiceUrl() { return mlServiceUrl; }
        public void setMlServiceUrl(String v) { this.mlServiceUrl = v; }
        public String getMlApiKey() { return mlApiKey; }
        public void setMlApiKey(String v) { this.mlApiKey = v; }
        public double getMlConfidenceThreshold() { return mlConfidenceThreshold; }
        public void setMlConfidenceThreshold(double v) { this.mlConfidenceThreshold = v; }
        public Duration getMlConnectTimeout() { return mlConnectTimeout; }
        public void setMlConnectTimeout(Duration v) { this.mlConnectTimeout = v; }
        public Duration getMlReadTimeout() { return mlReadTimeout; }
        public void setMlReadTimeout(Duration v) { this.mlReadTimeout = v; }
        public boolean isFailClosed() { return failClosed; }
        public void setFailClosed(boolean v) { this.failClosed = v; }
        public int getCircuitBreakerThreshold() { return circuitBreakerThreshold; }
        public void setCircuitBreakerThreshold(int v) { this.circuitBreakerThreshold = v; }
        public Duration getCircuitBreakerResetTimeout() { return circuitBreakerResetTimeout; }
        public void setCircuitBreakerResetTimeout(Duration v) { this.circuitBreakerResetTimeout = v; }
    }

    public static class Llm {
        private String apiKey = "";
        private String baseUrl = "https://api.groq.com/openai/v1/chat/completions";
        private String model = "llama-3.3-70b-versatile";

        /**
         * Without these the default RestTemplate waits forever. A hung upstream would pin
         * Tomcat worker threads until the pool is exhausted — a one-request denial of service.
         */
        private Duration connectTimeout = Duration.ofSeconds(5);
        private Duration readTimeout = Duration.ofSeconds(30);

        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = apiKey; }
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        public Duration getConnectTimeout() { return connectTimeout; }
        public void setConnectTimeout(Duration v) { this.connectTimeout = v; }
        public Duration getReadTimeout() { return readTimeout; }
        public void setReadTimeout(Duration v) { this.readTimeout = v; }
    }

    public static class RateLimit {
        private boolean enabled = true;

        /** Sustained requests per minute per client. */
        @Min(1)
        private int requestsPerMinute = 20;

        /** Short bursts above the sustained rate that are still accepted. */
        @Min(1)
        private int burst = 10;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getRequestsPerMinute() { return requestsPerMinute; }
        public void setRequestsPerMinute(int v) { this.requestsPerMinute = v; }
        public int getBurst() { return burst; }
        public void setBurst(int burst) { this.burst = burst; }
    }

    public static class Audit {
        /**
         * When false (the default and the only defensible setting for a privacy product),
         * the raw prompt is never written to the database — only the redacted form plus a
         * keyed hash for correlation.
         */
        private boolean storeRawPrompt = false;

        /** Key for the HMAC used to fingerprint prompts. Random per boot if left blank. */
        private String hashSecret = "";

        /** Audit rows older than this are deleted by the retention job. */
        private Duration retention = Duration.ofDays(30);

        public boolean isStoreRawPrompt() { return storeRawPrompt; }
        public void setStoreRawPrompt(boolean v) { this.storeRawPrompt = v; }
        public String getHashSecret() { return hashSecret; }
        public void setHashSecret(String v) { this.hashSecret = v; }
        public Duration getRetention() { return retention; }
        public void setRetention(Duration retention) { this.retention = retention; }
    }
}
