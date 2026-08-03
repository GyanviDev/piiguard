package com.piiguard.piiguard.audit;

import com.piiguard.piiguard.config.PiiGuardProperties;
import com.piiguard.piiguard.privacy.PiiEntityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The only path by which anything is written to the audit table.
 *
 * <p>Funnelling every write through one class is what makes "raw prompts are never persisted"
 * a property you can verify by reading a single file, rather than a claim you have to re-check
 * every time someone adds a {@code repository.save(...)} elsewhere. The controller used to call
 * the repository directly from two places, and one of those two was writing raw PII.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final AuditLogRepository repository;
    private final PiiGuardProperties.Audit config;
    private final SecretKeySpec hmacKey;

    public AuditService(AuditLogRepository repository, PiiGuardProperties props) {
        this.repository = repository;
        this.config = props.getAudit();
        this.hmacKey = new SecretKeySpec(resolveSecret(config.getHashSecret()), HMAC_ALGORITHM);
    }

    /**
     * A blank configured secret yields a random per-boot key rather than a constant fallback.
     * A hard-coded default would be in the repository, therefore known to everyone, therefore
     * no better than an unkeyed hash. The cost is that fingerprints do not correlate across
     * restarts — which is the correct trade to make by default, and is fixed by configuring a
     * real secret in any deployment that needs long-lived correlation.
     */
    private static byte[] resolveSecret(String configured) {
        if (configured != null && !configured.isBlank()) {
            return configured.getBytes(StandardCharsets.UTF_8);
        }
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        log.warn("piiguard.audit.hash-secret is not set — using a random per-boot key. "
               + "Prompt fingerprints will not correlate across restarts.");
        return random;
    }

    /**
     * Records one request. Failures here are logged and swallowed on purpose: the audit write
     * happens after the user's answer is ready, and losing an audit row is strictly better than
     * turning a successful, correctly-redacted request into a 500 because the database is
     * briefly unavailable. That trade would be the wrong way round in a system where the audit
     * log is the legal record of a financial transaction — here it is telemetry about a
     * stateless proxy call, and availability wins.
     */
    public void record(AuditLog.Builder builder, String rawPrompt) {
        try {
            builder.promptFingerprint(fingerprint(rawPrompt))
                   .promptLength(rawPrompt == null ? 0 : rawPrompt.length());

            if (config.isStoreRawPrompt()) {
                builder.rawPrompt(rawPrompt);
            }

            repository.save(builder.build());

        } catch (Exception e) {
            log.error("Failed to write audit record: {}", e.toString());
        }
    }

    /** Renders detection counts as {@code EMAIL=2, CARD=1}. Counts only — never values. */
    public static String summarise(Map<PiiEntityType, Integer> counts) {
        if (counts == null || counts.isEmpty()) {
            return "none";
        }
        return counts.entrySet().stream()
                .map(e -> e.getKey().name() + "=" + e.getValue())
                .collect(Collectors.joining(", "));
    }

    String fingerprint(String value) {
        if (value == null) {
            return "";
        }
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(hmacKey);
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /**
     * Storage limitation, enforced by a job rather than by intention. An audit table with no
     * expiry grows without bound and turns into a liability that outlives any justification for
     * keeping it — the same argument as the vault TTL, on a longer timescale.
     */
    @Scheduled(cron = "0 15 3 * * *")
    @Transactional
    public void enforceRetention() {
        Instant cutoff = Instant.now().minus(config.getRetention());
        int deleted = repository.deleteOlderThan(cutoff);
        if (deleted > 0) {
            log.info("Audit retention: deleted {} record(s) older than {}", deleted, cutoff);
        }
    }
}
