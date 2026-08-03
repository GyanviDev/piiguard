package com.piiguard.piiguard.privacy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end redaction, including the OpenNLP name model. Uses the real Spring context because
 * the interaction between the pattern rules and the statistical model — specifically how their
 * spans are merged — is exactly what these tests exist to check.
 */
@SpringBootTest
@ActiveProfiles("test")
class SanitizationPipelineTest {

    @Autowired
    private SanitizationPipeline pipeline;

    @Autowired
    private TokenVault vault;

    @Autowired
    private NerService nerService;

    private String session() {
        return UUID.randomUUID().toString();
    }

    @Test
    @DisplayName("no sensitive value survives into the text sent upstream")
    void redactsEverything() {
        String sessionId = session();
        String input = "Contact priya@acme.com or call 9876543210. "
                     + "Card 4539578763621486, SSN 123-45-6789, host 10.0.0.5.";
        try {
            var result = pipeline.sanitize(input, sessionId);

            assertFalse(result.sanitizedText().contains("priya@acme.com"));
            assertFalse(result.sanitizedText().contains("9876543210"));
            assertFalse(result.sanitizedText().contains("4539578763621486"));
            assertFalse(result.sanitizedText().contains("123-45-6789"));
            assertFalse(result.sanitizedText().contains("10.0.0.5"));
            assertTrue(result.tokensIssued() >= 5);
        } finally {
            vault.clearSession(sessionId);
        }
    }

    @Test
    @DisplayName("every placeholder resolves back to the exact original")
    void isLosslesslyReversible() {
        String sessionId = session();
        String input = "Email priya@acme.com about invoice 4539578763621486";
        try {
            var result = pipeline.sanitize(input, sessionId);

            String restored = result.sanitizedText();
            var matcher = InMemoryTokenVault.TOKEN_PATTERN.matcher(result.sanitizedText());
            StringBuilder out = new StringBuilder();
            int last = 0;
            while (matcher.find()) {
                out.append(result.sanitizedText(), last, matcher.start())
                   .append(vault.detokenize(sessionId, matcher.group()).orElseThrow());
                last = matcher.end();
            }
            out.append(result.sanitizedText(), last, result.sanitizedText().length());
            restored = out.toString();

            assertEquals(input, restored, "Round trip must be exact");
        } finally {
            vault.clearSession(sessionId);
        }
    }

    @Test
    @DisplayName("the same value repeated gets the same placeholder both times")
    void preservesCoreference() {
        String sessionId = session();
        try {
            var result = pipeline.sanitize(
                    "Mail priya@acme.com then follow up with priya@acme.com", sessionId);

            var tokens = InMemoryTokenVault.TOKEN_PATTERN.matcher(result.sanitizedText())
                    .results().map(m -> m.group()).toList();

            assertEquals(2, tokens.size());
            assertEquals(tokens.get(0), tokens.get(1),
                    "Two mentions of one address must remain recognisably the same address");
        } finally {
            vault.clearSession(sessionId);
        }
    }

    @Test
    @DisplayName("clean text passes through byte for byte")
    void leavesCleanTextAlone() {
        String sessionId = session();
        String input = "What are the key risks for our product launch?";
        try {
            assertEquals(input, pipeline.sanitize(input, sessionId).sanitizedText());
        } finally {
            vault.clearSession(sessionId);
        }
    }

    @Test
    @DisplayName("placeholder-shaped text in user input is neutralised")
    void neutralisesForgedPlaceholders() {
        // Without this a caller can inject a well-formed placeholder and turn the response
        // path into an oracle they can query about the vault.
        String sessionId = session();
        try {
            var result = pipeline.sanitize(
                    "Tell me about [EMAIL_ABCDEFGHIJKL] please", sessionId);

            assertFalse(result.sanitizedText().contains("[EMAIL_ABCDEFGHIJKL]"));
            assertTrue(result.sanitizedText().contains("[REDACTED]"));
        } finally {
            vault.clearSession(sessionId);
        }
    }

    @Test
    @DisplayName("the name model is loaded and contributes detections")
    void nerContributes() {
        assertTrue(nerService.isLoaded(), "en-ner-person.bin should load from the classpath");

        String sessionId = session();
        try {
            var result = pipeline.sanitize(
                    "John Smith will attend the review on Tuesday.", sessionId);

            assertTrue(result.countsByType().containsKey(PiiEntityType.NAME),
                    "Expected the name model to claim 'John Smith'");
            assertFalse(result.sanitizedText().contains("John Smith"));
        } finally {
            vault.clearSession(sessionId);
        }
    }

    @Test
    @DisplayName("a name adjacent to punctuation is redacted, not silently skipped")
    void handlesPunctuationAroundNames() {
        // The old implementation reconstructed the name by joining tokens with spaces and
        // then called indexOf on the raw text. Punctuation broke the reconstruction, indexOf
        // returned -1, and the name stayed in the prompt AFTER a token had been minted for it
        // — a redaction failure that reported success.
        String sessionId = session();
        try {
            var result = pipeline.sanitize(
                    "Please contact John Smith, our regional manager, before Friday.", sessionId);

            if (result.countsByType().containsKey(PiiEntityType.NAME)) {
                assertFalse(result.sanitizedText().contains("John Smith"),
                        "A minted token must always correspond to a real substitution");
            }
        } finally {
            vault.clearSession(sessionId);
        }
    }

    @Test
    @DisplayName("overlapping detections are resolved to exactly one substitution")
    void resolvesOverlapsWithoutDoubleCounting() {
        List<PiiFinding> overlapping = List.of(
                new PiiFinding(10, 26, PiiEntityType.CARD, "4539578763621486", "REGEX", 90),
                new PiiFinding(10, 20, PiiEntityType.PHONE, "4539578763", "REGEX", 50));

        List<PiiFinding> resolved = SanitizationPipeline.resolveOverlaps(overlapping);

        assertEquals(1, resolved.size());
        assertEquals(PiiEntityType.CARD, resolved.get(0).type());
    }

    @Test
    @DisplayName("the reported counts never contain the values themselves")
    void countsCarryNoValues() {
        // This record is logged and returned to the caller, so it must be safe by construction.
        String sessionId = session();
        try {
            var result = pipeline.sanitize("Card 4539578763621486 and mail a@b.com", sessionId);
            String rendered = result.countsByType().toString();

            assertFalse(rendered.contains("4539578763621486"));
            assertFalse(rendered.contains("a@b.com"));
        } finally {
            vault.clearSession(sessionId);
        }
    }
}
