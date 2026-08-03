package com.piiguard.piiguard.privacy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RegexSanitizerTest {

    private final RegexSanitizer sanitizer = new RegexSanitizer();

    private Set<PiiEntityType> typesIn(String text) {
        return sanitizer.detect(text).stream().map(PiiFinding::type).collect(Collectors.toSet());
    }

    // ── Structured identifiers ────────────────────────────────────────────────

    @Test
    void detectsEmail() {
        assertTrue(typesIn("Contact priya@acme.com please").contains(PiiEntityType.EMAIL));
    }

    @Test
    void detectsSsn() {
        assertTrue(typesIn("My SSN is 123-45-6789").contains(PiiEntityType.SSN));
    }

    @Test
    @DisplayName("SSNs in never-issued ranges are not flagged")
    void rejectsImpossibleSsn() {
        // 000, 666 and 900-999 area numbers are never issued, so anything in that shape is
        // some other identifier and redacting it would corrupt a legitimate prompt.
        assertFalse(typesIn("Reference 666-45-6789").contains(PiiEntityType.SSN));
        assertFalse(typesIn("Reference 000-45-6789").contains(PiiEntityType.SSN));
    }

    @Test
    void detectsIpv4() {
        assertTrue(typesIn("Server at 192.168.1.100 is down").contains(PiiEntityType.IP));
    }

    @Test
    @DisplayName("out-of-range octets are not IP addresses")
    void rejectsInvalidIpv4() {
        assertFalse(typesIn("Version 999.888.777.666 of the spec").contains(PiiEntityType.IP));
    }

    // ── Card numbers ──────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "4539578763621486",       // Visa, 16
            "4111 1111 1111 1111",    // spaced
            "5555-5555-5555-4444",    // hyphenated
            "378282246310005"         // Amex, 15
    })
    @DisplayName("valid cards of every common length are detected")
    void detectsValidCards(String card) {
        assertTrue(typesIn("Card " + card + " expires soon").contains(PiiEntityType.CARD),
                "Should have detected " + card);
    }

    @Test
    @DisplayName("15-digit Amex numbers are covered — the old length check rejected them")
    void amexIsNotLeaked() {
        // The original validator demanded exactly 16 digits, so every American Express and
        // Diners Club number in a prompt was forwarded to the model in the clear.
        assertTrue(typesIn("Amex 378282246310005").contains(PiiEntityType.CARD));
    }

    @Test
    @DisplayName("a 16-digit number that fails Luhn is not a card")
    void rejectsNonLuhnDigits() {
        assertFalse(typesIn("Order 1234567890123456 shipped").contains(PiiEntityType.CARD));
    }

    // ── Aadhaar ───────────────────────────────────────────────────────────────

    @Test
    void detectsValidAadhaar() {
        assertTrue(typesIn("Aadhaar 234567890124 on file").contains(PiiEntityType.AADHAAR));
    }

    @Test
    @DisplayName("twelve digits that fail the Verhoeff checksum are not an Aadhaar number")
    void rejectsInvalidAadhaar() {
        // Without the checksum, every 12-digit invoice number and epoch-millisecond timestamp
        // in an Indian deployment would be redacted.
        assertFalse(typesIn("Invoice 234567890125 issued").contains(PiiEntityType.AADHAAR));
    }

    // ── Credentials ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("API keys and tokens are detected — the commonest thing pasted into a chat box")
    void detectsSecrets() {
        assertTrue(typesIn("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE").contains(PiiEntityType.SECRET));
        assertTrue(typesIn("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                .contains(PiiEntityType.SECRET));
        assertTrue(typesIn("token ghp_16CharactersAndMoreABCDEFGHIJK").contains(PiiEntityType.SECRET));
    }

    // ── False positives ───────────────────────────────────────────────────────

    @Test
    @DisplayName("ordinary prose triggers nothing")
    void cleanTextProducesNoFindings() {
        assertTrue(sanitizer.detect("What is the capital of France?").isEmpty());
        assertTrue(sanitizer.detect("Summarize our Q3 revenue report and flag key risks").isEmpty());
    }

    @Test
    @DisplayName("repeated-digit placeholders are not treated as phone numbers")
    void rejectsPlaceholderPhoneNumbers() {
        assertFalse(typesIn("Call 0000000000 for support").contains(PiiEntityType.PHONE));
    }

    // ── Priority ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("a card number is claimed as a card, not carved up by the phone rule")
    void cardBeatsPhoneOnTheSameDigits() {
        List<PiiFinding> resolved = SanitizationPipeline.resolveOverlaps(
                sanitizer.detect("Pay with 4539578763621486 today"));

        assertEquals(1, resolved.size(), "The same digits must be claimed exactly once");
        assertEquals(PiiEntityType.CARD, resolved.get(0).type());
    }

    @Test
    @DisplayName("multiple distinct values are all found")
    void findsEveryValue() {
        Set<PiiEntityType> types = typesIn(
                "Email priya@acme.com, phone 9876543210, SSN 123-45-6789, IP 10.0.0.1");

        assertTrue(types.contains(PiiEntityType.EMAIL));
        assertTrue(types.contains(PiiEntityType.PHONE));
        assertTrue(types.contains(PiiEntityType.SSN));
        assertTrue(types.contains(PiiEntityType.IP));
    }

    @Test
    @DisplayName("a phone match covers only the number, not surrounding whitespace")
    void phoneSpanDoesNotSwallowNeighbouringCharacters() {
        // The optional country-code group could previously match zero digits plus a separator,
        // so the span began one character early and redaction deleted the preceding space.
        String text = "Reach us at 9876543210 today";
        PiiFinding phone = sanitizer.detect(text).stream()
                .filter(f -> f.type() == PiiEntityType.PHONE)
                .findFirst()
                .orElseThrow();

        assertEquals("9876543210", text.substring(phone.start(), phone.end()));
    }

    @Test
    @DisplayName("detection completes quickly on a maximum-length adversarial input")
    void isNotVulnerableToRedos() {
        // A 10,000-character worst case. If any pattern backtracks catastrophically this
        // never returns, so the assertion is really "the method terminates".
        String hostile = ("4444-4444-4444-444 " + "1".repeat(40) + " a@b").repeat(200);
        String input = hostile.substring(0, Math.min(hostile.length(), 10_000));

        long start = System.nanoTime();
        sanitizer.detect(input);
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        assertTrue(elapsedMillis < 2_000,
                "Detection took " + elapsedMillis + "ms — a pattern is backtracking");
    }
}
