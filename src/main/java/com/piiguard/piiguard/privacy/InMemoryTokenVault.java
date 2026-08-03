package com.piiguard.piiguard.privacy;

import com.piiguard.piiguard.config.PiiGuardProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * In-process token vault.
 *
 * <p>This class holds the only plaintext copy of the user's sensitive data anywhere in the
 * request path, so its failure modes are privacy failures. Four defects in the original
 * implementation are addressed here.
 *
 * <h3>1. Placeholders were guessable and collided</h3>
 * The old token body was {@code UUID.randomUUID().toString().substring(0, 4)} — four hex
 * characters, 65,536 possibilities. By the birthday bound a collision becomes more likely
 * than not after about 300 tokens in one session, and a collision is not a crash: the second
 * value silently overwrites the first, so re-injection hands the user <em>someone else's</em>
 * email address. Twelve characters from a 26-letter alphabet is roughly 56 bits, drawn from
 * {@link SecureRandom}.
 *
 * <h3>2. The alphabet is letters only, and that is load-bearing</h3>
 * Placeholders flow onward through the phone/card/SSN detectors and the numeric noise stage.
 * If a body could be all digits, {@code [PHONE_9876543210]} would itself look like a phone
 * number to the next detector, and the noise stage would happily rewrite the digits inside a
 * placeholder and make it undecodable. Excluding digits from the alphabet makes that class of
 * bug unrepresentable rather than merely unlikely.
 *
 * <h3>3. Secrets outlived their session</h3>
 * Cleanup happened only on the success path of the controller. Any exception between
 * tokenisation and cleanup — a network blip talking to the model was enough — stranded
 * plaintext PII in a process-lifetime map with no expiry. There is now an explicit
 * {@code finally} at the call site <em>and</em> a TTL sweeper here as the backstop, because a
 * privacy control that depends on the happy path is not a control.
 *
 * <h3>4. Nothing bounded growth</h3>
 * Unbounded maps are a denial-of-service primitive. Sessions and per-session entries are
 * capped, and exceeding a cap raises {@link VaultCapacityException} instead of quietly
 * discarding data — silent truncation in a redaction pipeline means unredacted output.
 */
@Component
public class InMemoryTokenVault implements TokenVault {

    private static final Logger log = LoggerFactory.getLogger(InMemoryTokenVault.class);

    /** Uppercase letters only — see the class comment; digits here would be a correctness bug. */
    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();

    /** Matches any placeholder this vault can emit. Shared with the sanitiser and the UI. */
    public static final Pattern TOKEN_PATTERN = Pattern.compile("\\[[A-Z]+_[A-Z]{8,32}]");

    private final SecureRandom random = new SecureRandom();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final PiiGuardProperties.Vault config;

    public InMemoryTokenVault(PiiGuardProperties props) {
        this.config = props.getVault();
    }

    @Override
    public String tokenize(String sessionId, PiiEntityType type, String realValue) {
        if (sessions.size() >= config.getMaxSessions() && !sessions.containsKey(sessionId)) {
            throw new VaultCapacityException("Vault is at capacity; refusing new session");
        }

        Session session = sessions.computeIfAbsent(sessionId, id -> new Session());

        synchronized (session) {
            String fingerprint = fingerprint(type, realValue);

            String existing = session.fingerprintToToken.get(fingerprint);
            if (existing != null) {
                return existing;
            }

            if (session.fingerprintToToken.size() >= config.getMaxEntriesPerSession()) {
                throw new VaultCapacityException(
                        "Session exceeded " + config.getMaxEntriesPerSession() + " distinct PII values");
            }

            String token = newToken(type, session);
            session.tokenToValue.put(token, realValue.toCharArray());
            session.fingerprintToToken.put(fingerprint, token);
            session.touch();
            return token;
        }
    }

    @Override
    public Optional<String> detokenize(String sessionId, String token) {
        Session session = sessions.get(sessionId);
        if (session == null) {
            return Optional.empty();
        }
        synchronized (session) {
            session.touch();
            char[] value = session.tokenToValue.get(token);
            return value == null ? Optional.empty() : Optional.of(new String(value));
        }
    }

    @Override
    public void clearSession(String sessionId) {
        Session session = sessions.remove(sessionId);
        if (session != null) {
            session.destroy();
        }
    }

    @Override
    public int activeSessions() {
        return sessions.size();
    }

    /**
     * Backstop for sessions the request path failed to clean up. Runs on a fixed delay taken
     * from configuration; the annotation needs a compile-time constant, so the interval is
     * expressed as a SpEL reference to the bound property.
     */
    @Scheduled(fixedDelayString = "${piiguard.vault.sweep-interval:PT1M}")
    public void evictExpiredSessions() {
        Duration ttl = config.getTtl();
        Instant cutoff = Instant.now().minus(ttl);
        int evicted = 0;

        for (Map.Entry<String, Session> entry : sessions.entrySet()) {
            if (entry.getValue().lastAccess().isBefore(cutoff)
                    && sessions.remove(entry.getKey(), entry.getValue())) {
                entry.getValue().destroy();
                evicted++;
            }
        }

        if (evicted > 0) {
            // Session ids are logged, values never are. A log line that helps you debug a
            // redaction bug by printing the redacted value defeats the entire system.
            log.warn("Swept {} expired vault session(s) — these leaked past request cleanup", evicted);
        }
    }

    private String newToken(PiiEntityType type, Session session) {
        // Retry on the (astronomically unlikely) collision rather than assuming it away.
        for (int attempt = 0; attempt < 5; attempt++) {
            StringBuilder body = new StringBuilder(config.getTokenLength());
            for (int i = 0; i < config.getTokenLength(); i++) {
                body.append(ALPHABET[random.nextInt(ALPHABET.length)]);
            }
            String token = "[" + type.name() + "_" + body + "]";
            if (!session.tokenToValue.containsKey(token)) {
                return token;
            }
        }
        throw new VaultCapacityException("Unable to allocate a unique token");
    }

    /**
     * Deduplication key. Hashing rather than using the value itself as a map key means the
     * vault never keeps a second, un-wipeable plaintext copy of the secret just to answer
     * "have I seen this before?".
     */
    private String fingerprint(PiiEntityType type, String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(type.name().getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static final class Session {
        final Map<String, char[]> tokenToValue = new ConcurrentHashMap<>();
        final Map<String, String> fingerprintToToken = new ConcurrentHashMap<>();
        private volatile Instant lastAccess = Instant.now();

        void touch() {
            lastAccess = Instant.now();
        }

        Instant lastAccess() {
            return lastAccess;
        }

        /**
         * Values are held as {@code char[]} rather than {@code String} so they can actually be
         * overwritten. A {@code String} is immutable and interned into the heap until the
         * collector happens to run, which means a heap dump taken minutes after a session ended
         * still contains the customer's card number. Zeroing is not perfect — the JVM may have
         * copied the array during a GC cycle — but it removes the copy we control, and it is the
         * standard practice that {@code char[]} passwords exist for.
         */
        void destroy() {
            tokenToValue.values().forEach(chars -> Arrays.fill(chars, '\0'));
            tokenToValue.clear();
            fingerprintToToken.clear();
        }
    }
}
