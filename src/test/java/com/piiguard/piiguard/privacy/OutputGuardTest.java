package com.piiguard.piiguard.privacy;

import com.piiguard.piiguard.config.PiiGuardProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The return path. None of this existed before — the original design inspected the request and
 * trusted the response completely.
 */
class OutputGuardTest {

    private OutputGuard guard;
    private InMemoryTokenVault vault;

    @BeforeEach
    void setUp() {
        guard = new OutputGuard(new RegexSanitizer());
        vault = new InMemoryTokenVault(new PiiGuardProperties());
    }

    @Test
    @DisplayName("placeholders this session issued are restored")
    void restoresOwnTokens() {
        String token = vault.tokenize("s1", PiiEntityType.EMAIL, "priya@acme.com");

        OutputGuard.GuardedResponse result =
                guard.process("I will email " + token + " today.", "s1", vault);

        assertEquals("I will email priya@acme.com today.", result.text());
        assertEquals(1, result.tokensRestored());
        assertTrue(result.isClean());
    }

    @Test
    @DisplayName("a placeholder this session never issued is flagged, not silently passed through")
    void reportsUnknownTokens() {
        OutputGuard.GuardedResponse result =
                guard.process("Value is [EMAIL_ZZZZZZZZZZZZ].", "s1", vault);

        assertEquals(1, result.unknownTokens().size());
        assertEquals(0, result.tokensRestored());
        assertFalse(result.isClean());
        // Left visible rather than erased, so the user is not shown a sentence that reads as
        // though it were complete.
        assertTrue(result.text().contains("[EMAIL_ZZZZZZZZZZZZ]"));
    }

    @Test
    @DisplayName("a placeholder from another session does not resolve")
    void doesNotCrossSessions() {
        String token = vault.tokenize("other-session", PiiEntityType.EMAIL, "victim@acme.com");

        OutputGuard.GuardedResponse result = guard.process("See " + token, "s1", vault);

        assertFalse(result.text().contains("victim@acme.com"));
        assertEquals(1, result.unknownTokens().size());
    }

    @Test
    @DisplayName("sensitive-looking values the model invented are reported")
    void detectsModelGeneratedPii() {
        // The model never sees real data, so it cannot leak ours — but it can fabricate a
        // plausible card number and state it as fact, and a user reading a privacy proxy's
        // output will reasonably assume someone checked.
        OutputGuard.GuardedResponse result = guard.process(
                "A typical card number looks like 4539578763621486.", "s1", vault);

        assertTrue(result.generatedPiiTypes().contains(PiiEntityType.CARD));
        assertFalse(result.isClean());
    }

    @Test
    @DisplayName("a clean response is reported clean")
    void cleanResponseIsClean() {
        OutputGuard.GuardedResponse result =
                guard.process("The capital of France is Paris.", "s1", vault);

        assertTrue(result.isClean());
        assertEquals(0, result.tokensRestored());
    }

    @Test
    @DisplayName("null and empty responses are handled")
    void handlesEmptyOutput() {
        assertEquals("", guard.process(null, "s1", vault).text());
        assertEquals("", guard.process("", "s1", vault).text());
    }

    @Test
    @DisplayName("restoration is literal — a real value containing $ or \\ is not mangled")
    void restoresLiterally() {
        // Regex replacement treats $1 and backslashes as capture-group syntax. Getting this
        // wrong corrupts the very values the system promised to return intact.
        String token = vault.tokenize("s1", PiiEntityType.SECRET, "pa$$w0rd\\test$1");

        String out = guard.process("Key: " + token, "s1", vault).text();

        assertEquals("Key: pa$$w0rd\\test$1", out);
    }

    @Test
    @DisplayName("several placeholders in one response are all restored")
    void restoresMultipleTokens() {
        String email = vault.tokenize("s1", PiiEntityType.EMAIL, "a@acme.com");
        String name = vault.tokenize("s1", PiiEntityType.NAME, "Priya");

        OutputGuard.GuardedResponse result =
                guard.process("Tell " + name + " to write to " + email + ".", "s1", vault);

        assertEquals("Tell Priya to write to a@acme.com.", result.text());
        assertEquals(2, result.tokensRestored());
    }
}
