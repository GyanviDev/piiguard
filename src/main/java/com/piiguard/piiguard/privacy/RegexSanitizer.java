package com.piiguard.piiguard.privacy;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pattern-based detection of structured sensitive values.
 *
 * <p>Regex is the right tool for anything with a grammar — an email address, a card number,
 * a JWT — and the wrong tool for anything that depends on meaning, which is why person names
 * are handled by {@link NerService} instead. The two feed the same span-resolution pass.
 *
 * <h3>What changed and why</h3>
 *
 * <p><b>Detection replaces text in one pass, not five.</b> The original ran each pattern over
 * the string in sequence, each pass rewriting the input for the next. That made correctness
 * depend on declaration order in a way nothing documented or tested: {@code PHONE} ran before
 * {@code SSN} and {@code CARD}, and it only failed to swallow their digits by accident of how
 * word boundaries fell. Emitting spans and resolving overlaps by explicit priority makes the
 * intent — most specific detector wins — a stated rule instead of a coincidence.
 *
 * <p><b>Validators, not just shapes.</b> A pattern that matches sixteen digits also matches an
 * order number. Luhn for cards, the Verhoeff checksum for Aadhaar, octet range checks for IPv4
 * and the reserved-range rules for SSNs cut the false-positive rate sharply. False positives
 * are not harmless here: every one of them corrupts a legitimate prompt and quietly degrades
 * the answer the user gets, which is exactly how a privacy tool earns a reputation for being
 * something to switch off.
 *
 * <p><b>Credentials are now in scope.</b> The commonest sensitive thing a developer pastes
 * into a chat assistant is not a phone number, it is an API key out of a stack trace. Unlike a
 * phone number, a leaked key is immediately actionable by whoever receives it.
 *
 * <p><b>Every pattern is anchored and bounded.</b> No nested unbounded quantifiers, so no
 * catastrophic backtracking on adversarial input — see {@code AdversarialHarnessService} for
 * the same problem in its more dangerous form.
 */
@Component
public class RegexSanitizer {

    /**
     * Detection rule. Priority decides who wins when two rules claim the same characters:
     * a string of digits that satisfies both the card and the phone pattern is a card.
     */
    private record Rule(PiiEntityType type, Pattern pattern, Predicate<String> validator, int priority) {
        Rule(PiiEntityType type, String regex, int priority) {
            this(type, Pattern.compile(regex), v -> true, priority);
        }
        Rule(PiiEntityType type, String regex, Predicate<String> validator, int priority) {
            this(type, Pattern.compile(regex), validator, priority);
        }
    }

    private static final List<Rule> RULES = List.of(

        // ── Credentials (priority 100) ────────────────────────────────────────────
        // Deliberately first: a bearer token embedded in a URL would otherwise be picked
        // apart by narrower rules and only partially redacted, which is worse than useless.
        new Rule(PiiEntityType.SECRET,
                "-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----[\\s\\S]{0,4096}?-----END(?: [A-Z]+)* PRIVATE KEY-----", 100),
        new Rule(PiiEntityType.SECRET, "\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b", 100),
        new Rule(PiiEntityType.SECRET, "\\bAKIA[0-9A-Z]{16}\\b", 100),
        new Rule(PiiEntityType.SECRET, "\\bgh[pousr]_[A-Za-z0-9]{20,255}\\b", 100),
        new Rule(PiiEntityType.SECRET, "\\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,128}\\b", 100),
        new Rule(PiiEntityType.SECRET, "\\bgsk_[A-Za-z0-9]{20,128}\\b", 100),
        new Rule(PiiEntityType.SECRET, "\\bxox[baprs]-[A-Za-z0-9-]{10,255}\\b", 100),

        // ── Government and financial identifiers (priority 90) ────────────────────
        new Rule(PiiEntityType.CARD,
                "\\b(?:\\d[ -]?){12,18}\\d\\b", RegexSanitizer::isValidCard, 90),
        // US SSN: area 000/666/900-999, group 00 and serial 0000 are never issued.
        new Rule(PiiEntityType.SSN,
                "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b", 90),
        new Rule(PiiEntityType.AADHAAR,
                "\\b[2-9]\\d{3}[ -]?\\d{4}[ -]?\\d{4}\\b", RegexSanitizer::isValidAadhaar, 90),
        new Rule(PiiEntityType.PAN, "\\b[A-Z]{5}\\d{4}[A-Z]\\b", 90),
        new Rule(PiiEntityType.IBAN, "\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b", 90),
        new Rule(PiiEntityType.PASSPORT, "\\b[A-PR-WY][1-9]\\d\\s?\\d{4}[1-9]\\b", 90),

        // ── Contact details (priority 80-50) ──────────────────────────────────────
        new Rule(PiiEntityType.EMAIL,
                "\\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}\\b", 80),
        new Rule(PiiEntityType.IP,
                "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b", RegexSanitizer::isValidIpv4, 70),
        new Rule(PiiEntityType.IP,
                "\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b", 70),
        new Rule(PiiEntityType.DOB,
                "\\b(?:0?[1-9]|[12]\\d|3[01])[/-](?:0?[1-9]|1[0-2])[/-](?:19|20)\\d{2}\\b", 60),
        new Rule(PiiEntityType.IFSC, "\\b[A-Z]{4}0[A-Z0-9]{6}\\b", 55),

        // Broadest rule, so it runs at the lowest priority and never wins a contested span.
        // The country-code group is optional as a WHOLE — written as `\d{0,3}[-.\s]?` it could
        // match zero digits followed by a separator, so the rule consumed the space before the
        // number and redaction quietly deleted a character it did not own ("(a@b.com, 98765…)"
        // came back as "(a@b.com,[PHONE_…])"). Harmless to privacy, but a redactor that alters
        // text outside the value it matched is one you cannot reason about.
        new Rule(PiiEntityType.PHONE,
                "(?:\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b",
                RegexSanitizer::isPlausiblePhone, 50)
    );

    /** Reports every match without modifying the text. Rewriting happens once, downstream. */
    public List<PiiFinding> detect(String text) {
        List<PiiFinding> findings = new ArrayList<>();

        for (Rule rule : RULES) {
            Matcher matcher = rule.pattern().matcher(text);
            while (matcher.find()) {
                String value = matcher.group();
                if (rule.validator().test(value)) {
                    findings.add(new PiiFinding(
                            matcher.start(), matcher.end(), rule.type(), value, "REGEX", rule.priority()));
                }
            }
        }
        return findings;
    }

    /** Exposed so {@code /api/status} reports the real number instead of a hard-coded one. */
    public int ruleCount() {
        return RULES.size();
    }

    // ── Validators ────────────────────────────────────────────────────────────────

    /**
     * Luhn check digit, as used by every major card scheme. Also enforces a 13-19 digit
     * length: the old implementation demanded exactly 16, which rejected Amex (15) and
     * Diners (14) outright — those numbers were forwarded to the model in the clear.
     */
    static boolean isValidCard(String candidate) {
        String digits = candidate.replaceAll("[^0-9]", "");
        if (digits.length() < 13 || digits.length() > 19) {
            return false;
        }
        int sum = 0;
        boolean doubling = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int digit = digits.charAt(i) - '0';
            if (doubling) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            doubling = !doubling;
        }
        return sum % 10 == 0;
    }

    /**
     * Verhoeff checksum, the scheme India's UIDAI uses for Aadhaar numbers. Without it any
     * twelve digits beginning 2-9 would be redacted as an Aadhaar, which in an Indian
     * deployment means mangling order ids, invoice numbers and timestamps constantly.
     */
    static boolean isValidAadhaar(String candidate) {
        String digits = candidate.replaceAll("[^0-9]", "");
        if (digits.length() != 12) {
            return false;
        }
        int checksum = 0;
        for (int i = 0; i < digits.length(); i++) {
            int digit = digits.charAt(digits.length() - 1 - i) - '0';
            checksum = VERHOEFF_D[checksum][VERHOEFF_P[i % 8][digit]];
        }
        return checksum == 0;
    }

    static boolean isValidIpv4(String candidate) {
        for (String octet : candidate.split("\\.")) {
            if (octet.length() > 3 || Integer.parseInt(octet) > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * Rejects the obvious false positives a loose phone pattern attracts — long digit runs
     * that are really identifiers, and repeated digits that are placeholders rather than
     * anyone's number.
     */
    static boolean isPlausiblePhone(String candidate) {
        String digits = candidate.replaceAll("[^0-9]", "");
        if (digits.length() < 10 || digits.length() > 15) {
            return false;
        }
        return digits.chars().distinct().count() > 2;
    }

    // Verhoeff dihedral-group multiplication and permutation tables.
    private static final int[][] VERHOEFF_D = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
        {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
        {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
        {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
        {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
        {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
        {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
        {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
        {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
        {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
    };

    private static final int[][] VERHOEFF_P = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
        {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
        {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
        {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
        {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
        {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
        {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
        {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}
    };
}
