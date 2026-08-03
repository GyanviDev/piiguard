package com.piiguard.piiguard.privacy;

import com.piiguard.piiguard.config.PiiGuardProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the vault, written against the specific defects the rewrite closed rather than
 * against the happy path. A test that only proves {@code tokenize} then {@code detokenize}
 * round-trips would have passed against the original implementation too, including on the day
 * it was silently handing one user's email address to another.
 */
class InMemoryTokenVaultTest {

    private InMemoryTokenVault vault;
    private PiiGuardProperties props;

    @BeforeEach
    void setUp() {
        props = new PiiGuardProperties();
        vault = new InMemoryTokenVault(props);
    }

    @Test
    @DisplayName("round-trips a value within its session")
    void roundTrip() {
        String token = vault.tokenize("s1", PiiEntityType.EMAIL, "priya@acme.com");

        assertTrue(token.startsWith("[EMAIL_"));
        assertEquals("priya@acme.com", vault.detokenize("s1", token).orElseThrow());
    }

    @Test
    @DisplayName("sessions are isolated — one session cannot resolve another's placeholder")
    void sessionsAreIsolated() {
        String token = vault.tokenize("session-a", PiiEntityType.EMAIL, "alice@acme.com");

        assertTrue(vault.detokenize("session-b", token).isEmpty(),
                "A placeholder must not resolve outside the session that issued it");
    }

    @Test
    @DisplayName("the same value in one session gets the same placeholder")
    void repeatedValuesShareAToken() {
        // Not an optimisation. "Priya emailed Priya's manager" must stay recognisably about
        // one person, or the model answers a different question than the one that was asked.
        String first = vault.tokenize("s1", PiiEntityType.NAME, "Priya");
        String second = vault.tokenize("s1", PiiEntityType.NAME, "Priya");

        assertEquals(first, second);
    }

    @Test
    @DisplayName("different values never share a placeholder")
    void distinctValuesGetDistinctTokens() {
        String a = vault.tokenize("s1", PiiEntityType.EMAIL, "a@acme.com");
        String b = vault.tokenize("s1", PiiEntityType.EMAIL, "b@acme.com");

        assertFalse(a.equals(b));
        assertEquals("a@acme.com", vault.detokenize("s1", a).orElseThrow());
        assertEquals("b@acme.com", vault.detokenize("s1", b).orElseThrow());
    }

    @Test
    @DisplayName("token bodies contain no digits, so no numeric detector can match inside one")
    void tokenBodiesAreAlphabetic() {
        // This is the invariant that keeps placeholders safe from the phone/card detectors and
        // from the numeric noise stage. If it ever breaks, redaction silently corrupts itself.
        for (int i = 0; i < 200; i++) {
            String token = vault.tokenize("s1", PiiEntityType.PHONE, "value-" + i);
            String body = token.substring(token.indexOf('_') + 1, token.length() - 1);
            assertTrue(body.matches("[A-Z]+"), "Token body must be letters only, was: " + body);
        }
    }

    @Test
    @DisplayName("500 tokens in one session produce zero collisions")
    void noCollisionsAtScale() {
        // The old 4-hex-character token had a 65,536-value space; by the birthday bound a
        // collision is more likely than not after roughly 300 tokens, and a collision meant
        // one value overwriting another and the WRONG secret being restored to the user.
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            assertTrue(seen.add(vault.tokenize("s1", PiiEntityType.EMAIL, "user" + i + "@acme.com")),
                    "Token collision at iteration " + i);
        }
    }

    @Test
    @DisplayName("clearSession destroys the secrets")
    void clearSessionRemovesEverything() {
        String token = vault.tokenize("s1", PiiEntityType.SSN, "123-45-6789");
        vault.clearSession("s1");

        assertTrue(vault.detokenize("s1", token).isEmpty());
        assertEquals(0, vault.activeSessions());
    }

    @Test
    @DisplayName("clearSession is idempotent")
    void clearSessionTwiceIsSafe() {
        vault.tokenize("s1", PiiEntityType.SSN, "123-45-6789");
        vault.clearSession("s1");

        // The controller's finally block can run after an exception path that already cleaned
        // up, so this must not throw.
        vault.clearSession("s1");
        assertEquals(0, vault.activeSessions());
    }

    @Test
    @DisplayName("the TTL sweeper destroys sessions the request path failed to clean up")
    void sweeperEvictsExpiredSessions() throws InterruptedException {
        props.getVault().setTtl(Duration.ofMillis(50));
        String token = vault.tokenize("abandoned", PiiEntityType.CARD, "4111111111111111");
        assertEquals(1, vault.activeSessions());

        Thread.sleep(120);
        vault.evictExpiredSessions();

        assertEquals(0, vault.activeSessions(), "Expired session should have been swept");
        assertTrue(vault.detokenize("abandoned", token).isEmpty());
    }

    @Test
    @DisplayName("the sweeper leaves live sessions alone")
    void sweeperKeepsFreshSessions() {
        props.getVault().setTtl(Duration.ofMinutes(5));
        vault.tokenize("live", PiiEntityType.EMAIL, "x@acme.com");

        vault.evictExpiredSessions();

        assertEquals(1, vault.activeSessions());
    }

    @Test
    @DisplayName("per-session capacity is enforced rather than silently truncating")
    void perSessionCapacityIsEnforced() {
        props.getVault().setMaxEntriesPerSession(3);
        vault.tokenize("s1", PiiEntityType.EMAIL, "a@x.com");
        vault.tokenize("s1", PiiEntityType.EMAIL, "b@x.com");
        vault.tokenize("s1", PiiEntityType.EMAIL, "c@x.com");

        assertThrows(TokenVault.VaultCapacityException.class,
                () -> vault.tokenize("s1", PiiEntityType.EMAIL, "d@x.com"),
                "Exceeding capacity must raise, not drop data — a dropped redaction is a leak");
    }

    @Test
    @DisplayName("global session capacity is enforced")
    void globalCapacityIsEnforced() {
        props.getVault().setMaxSessions(2);
        vault.tokenize("s1", PiiEntityType.EMAIL, "a@x.com");
        vault.tokenize("s2", PiiEntityType.EMAIL, "b@x.com");

        assertThrows(TokenVault.VaultCapacityException.class,
                () -> vault.tokenize("s3", PiiEntityType.EMAIL, "c@x.com"));

        // An existing session must still work while the vault is full, so in-flight requests
        // are not broken by pressure created after they started.
        vault.tokenize("s1", PiiEntityType.EMAIL, "another@x.com");
    }

    @Test
    @DisplayName("concurrent tokenisation loses nothing and mixes nothing up")
    void concurrentAccessIsCorrect() throws InterruptedException {
        int threads = 16;
        int opsPerThread = 100;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger mismatches = new AtomicInteger();

        props.getVault().setMaxEntriesPerSession(threads * opsPerThread + 10);

        for (int t = 0; t < threads; t++) {
            final int threadId = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < opsPerThread; i++) {
                        String expected = "user-" + threadId + "-" + i + "@acme.com";
                        String token = vault.tokenize("shared", PiiEntityType.EMAIL, expected);
                        // The real concurrency risk is not an exception, it is getting back
                        // SOMEONE ELSE'S value. That is what is asserted.
                        if (!expected.equals(vault.detokenize("shared", token).orElse(null))) {
                            mismatches.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    mismatches.incrementAndGet();
                } finally {
                    done.countDown();
                }
            });
        }

        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "Threads did not finish in time");
        pool.shutdownNow();

        assertEquals(0, mismatches.get(), "Concurrent access returned a value from another entry");
    }
}
