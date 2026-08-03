package com.piiguard.piiguard.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * One immutable record of a request passing through the proxy.
 *
 * <h3>The most serious defect in the original project lived in this table</h3>
 *
 * <p>The previous entity had a column named {@code originalPrompt}, and the controller wrote
 * the user's raw, unredacted prompt into it on every single request — including the ones it
 * had just blocked as attacks. A product whose entire purpose is preventing sensitive text
 * from being persisted to somewhere it does not belong was persisting it, in plaintext, to its
 * own database. Every card number, national ID and API key the proxy successfully kept away
 * from the model was written to disk instead. And {@code GET /api/audit} returned the whole
 * table to unauthenticated callers.
 *
 * <p>It is worth being precise about why this is not merely untidy. The system's promise is
 * that real values exist in one place — the in-memory vault — for the lifetime of one request
 * and are then destroyed. The audit table quietly made that false. Any breach of the database,
 * any backup copied to a laptop, any over-broad read grant, exposed exactly the data the
 * product claims to protect. Under GDPR this is the difference between processing data and
 * retaining it: the second needs a lawful basis, a retention period and a deletion path, none
 * of which existed.
 *
 * <h3>What is stored now</h3>
 *
 * <ul>
 *   <li><b>A keyed fingerprint</b> instead of the prompt. HMAC-SHA-256, not a plain hash: a
 *       plain hash of a short, structured value like a phone number is trivially reversed with
 *       a rainbow table, and the secret key is what makes that attack require the key too.
 *       Identical prompts still produce identical fingerprints, so abuse patterns and repeat
 *       offenders remain detectable — the investigative value survives, the exposure does not.</li>
 *   <li><b>The redacted prompt</b>, which by construction contains placeholders where the
 *       sensitive values were. This is the audit's evidentiary content and it is safe by the
 *       same argument that makes it safe to send to the model.</li>
 *   <li><b>Counts by type</b>, never values — "2 EMAIL, 1 CARD" answers the compliance
 *       question without reproducing the data.</li>
 * </ul>
 *
 * <p>Retaining the raw prompt remains possible via {@code piiguard.audit.store-raw-prompt},
 * because some regulated environments genuinely require it. It defaults to off, so choosing it
 * is a deliberate act by someone who knows what they are accepting.
 */
@Entity
@Table(name = "audit_log", indexes = {
        @Index(name = "idx_audit_created", columnList = "createdAt"),
        @Index(name = "idx_audit_fingerprint", columnList = "promptFingerprint"),
        @Index(name = "idx_audit_attack", columnList = "attackDetected")
})
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 36)
    private String sessionId;

    /** HMAC-SHA-256 of the raw prompt. Correlates repeats without storing content. */
    @Column(nullable = false, length = 64)
    private String promptFingerprint;

    /** Length is useful for spotting abuse and costs nothing in disclosure. */
    private int promptLength;

    /** Placeholders only — no sensitive values by construction. */
    @Column(length = 12_000)
    private String redactedPrompt;

    /** Populated only when {@code piiguard.audit.store-raw-prompt} is explicitly enabled. */
    @Column(length = 12_000)
    private String rawPrompt;

    /** Human-readable tally such as {@code EMAIL=2, CARD=1}. Counts, never values. */
    @Column(length = 512)
    private String piiSummary;

    private boolean attackDetected;

    @Column(length = 32)
    private String detectionMethod;

    /** The specific rule that fired, so a block can be explained and a false positive traced. */
    @Column(length = 64)
    private String detectionRule;

    private double detectionConfidence;

    /** {@code OK}, {@code BLOCKED}, {@code LLM_UNAVAILABLE}, {@code ERROR}. */
    @Column(length = 32)
    private String outcome;

    private int dpValuesNoised;

    private long latencyMillis;

    @Column(nullable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    protected AuditLog() {
        // Required by JPA.
    }

    private AuditLog(Builder builder) {
        this.sessionId = builder.sessionId;
        this.promptFingerprint = builder.promptFingerprint;
        this.promptLength = builder.promptLength;
        this.redactedPrompt = builder.redactedPrompt;
        this.rawPrompt = builder.rawPrompt;
        this.piiSummary = builder.piiSummary;
        this.attackDetected = builder.attackDetected;
        this.detectionMethod = builder.detectionMethod;
        this.detectionRule = builder.detectionRule;
        this.detectionConfidence = builder.detectionConfidence;
        this.outcome = builder.outcome;
        this.dpValuesNoised = builder.dpValuesNoised;
        this.latencyMillis = builder.latencyMillis;
    }

    public static Builder builder() {
        return new Builder();
    }

    public Long getId() { return id; }
    public String getSessionId() { return sessionId; }
    public String getPromptFingerprint() { return promptFingerprint; }
    public int getPromptLength() { return promptLength; }
    public String getRedactedPrompt() { return redactedPrompt; }
    public String getRawPrompt() { return rawPrompt; }
    public String getPiiSummary() { return piiSummary; }
    public boolean isAttackDetected() { return attackDetected; }
    public String getDetectionMethod() { return detectionMethod; }
    public String getDetectionRule() { return detectionRule; }
    public double getDetectionConfidence() { return detectionConfidence; }
    public String getOutcome() { return outcome; }
    public int getDpValuesNoised() { return dpValuesNoised; }
    public long getLatencyMillis() { return latencyMillis; }
    public Instant getCreatedAt() { return createdAt; }

    /**
     * A builder rather than a nine-argument constructor. The old five-argument constructor
     * took {@code (sessionId, originalPrompt, sanitizedPrompt, ...)} — two adjacent strings
     * with indistinguishable types, where swapping them writes raw PII into the field meant
     * for redacted text and the compiler cannot object. Named setters make that class of
     * mistake impossible to make silently.
     */
    public static final class Builder {
        private String sessionId;
        private String promptFingerprint;
        private int promptLength;
        private String redactedPrompt;
        private String rawPrompt;
        private String piiSummary;
        private boolean attackDetected;
        private String detectionMethod = "NONE";
        private String detectionRule = "none";
        private double detectionConfidence;
        private String outcome = "OK";
        private int dpValuesNoised;
        private long latencyMillis;

        public Builder sessionId(String v) { this.sessionId = v; return this; }
        public Builder promptFingerprint(String v) { this.promptFingerprint = v; return this; }
        public Builder promptLength(int v) { this.promptLength = v; return this; }
        public Builder redactedPrompt(String v) { this.redactedPrompt = v; return this; }
        public Builder rawPrompt(String v) { this.rawPrompt = v; return this; }
        public Builder piiSummary(String v) { this.piiSummary = v; return this; }
        public Builder attackDetected(boolean v) { this.attackDetected = v; return this; }
        public Builder detectionMethod(String v) { this.detectionMethod = v; return this; }
        public Builder detectionRule(String v) { this.detectionRule = v; return this; }
        public Builder detectionConfidence(double v) { this.detectionConfidence = v; return this; }
        public Builder outcome(String v) { this.outcome = v; return this; }
        public Builder dpValuesNoised(int v) { this.dpValuesNoised = v; return this; }
        public Builder latencyMillis(long v) { this.latencyMillis = v; return this; }

        public AuditLog build() {
            return new AuditLog(this);
        }
    }
}
