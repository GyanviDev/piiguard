package com.piiguard.piiguard.privacy;

import com.piiguard.piiguard.config.PiiGuardProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

/**
 * Turns a raw prompt into one that is safe to send to a third party.
 *
 * <p>The original controller inlined this as three sequential string rewrites, each consuming
 * the previous one's output. Extracting it buys three things that matter: the ordering rules
 * become explicit and testable without booting a web server, the stages can report what they
 * found instead of only what they changed, and a bug in redaction can be reproduced in a unit
 * test rather than by curling an endpoint and reading a diff.
 *
 * <h3>The pipeline</h3>
 * <ol>
 *   <li><b>Neutralise placeholder look-alikes.</b> Anything in the user's own text shaped like
 *       one of our tokens is defanged first — see {@link #neutraliseTokenLookalikes}.</li>
 *   <li><b>Detect.</b> Pattern rules, the name model and the name lexicon all run over the
 *       <em>same</em> unmodified text and all report character spans. None can hide matches
 *       from the others by rewriting the input underneath them, which is what the old
 *       sequential design did.</li>
 *   <li><b>Resolve overlaps.</b> Highest priority wins, then the longest match. A digit string
 *       that satisfies both the card and the phone rule is redacted as a card, once.</li>
 *   <li><b>Substitute, right to left.</b> Replacing from the end means earlier offsets stay
 *       valid, so no index arithmetic is needed and no off-by-one is possible.</li>
 * </ol>
 */
@Component
public class SanitizationPipeline {

    private static final Logger log = LoggerFactory.getLogger(SanitizationPipeline.class);

    private final RegexSanitizer regexSanitizer;
    private final NerService nerService;
    private final GazetteerNameDetector gazetteer;
    private final TokenVault vault;
    private final PiiGuardProperties props;

    public SanitizationPipeline(RegexSanitizer regexSanitizer,
                                NerService nerService,
                                GazetteerNameDetector gazetteer,
                                TokenVault vault,
                                PiiGuardProperties props) {
        this.regexSanitizer = regexSanitizer;
        this.nerService = nerService;
        this.gazetteer = gazetteer;
        this.vault = vault;
        this.props = props;
    }

    /**
     * @param sanitizedText  text with every detected value replaced by a placeholder
     * @param countsByType   how many values of each kind were redacted — counts only, never
     *                       the values themselves, because this record is logged and returned
     * @param tokensIssued   total placeholders minted
     * @param truncated      true when a capacity limit stopped redaction part-way
     */
    public record SanitizationResult(
            String sanitizedText,
            Map<PiiEntityType, Integer> countsByType,
            int tokensIssued,
            boolean truncated) {

        public boolean foundAnything() {
            return tokensIssued > 0;
        }

        public int highestSeverity() {
            return countsByType.keySet().stream()
                    .mapToInt(PiiEntityType::severity)
                    .max()
                    .orElse(0);
        }
    }

    public SanitizationResult sanitize(String rawPrompt, String sessionId) {
        String text = neutraliseTokenLookalikes(rawPrompt);

        // Three detectors, one unmodified input. None can hide a match from the others by
        // rewriting the text underneath them, which is what the old sequential design did.
        List<PiiFinding> findings = new ArrayList<>();
        findings.addAll(regexSanitizer.detect(text));
        findings.addAll(nerService.detect(text));
        findings.addAll(gazetteer.detect(text));

        List<PiiFinding> resolved = resolveOverlaps(findings);

        StringBuilder out = new StringBuilder(text);
        Map<PiiEntityType, Integer> counts = new EnumMap<>(PiiEntityType.class);
        int issued = 0;
        boolean truncated = false;

        // Right to left: every replacement is at a higher offset than the next one applied,
        // so no already-computed span is ever invalidated.
        for (int i = resolved.size() - 1; i >= 0; i--) {
            PiiFinding finding = resolved.get(i);
            try {
                String token = vault.tokenize(sessionId, finding.type(), finding.value());
                out.replace(finding.start(), finding.end(), token);
                counts.merge(finding.type(), 1, Integer::sum);
                issued++;
            } catch (TokenVault.VaultCapacityException e) {
                // Reversible redaction is unavailable, but forwarding the raw value is not an
                // option. Substituting a non-reversible marker degrades the answer and keeps
                // the guarantee — failing safe rather than failing open.
                out.replace(finding.start(), finding.end(), "[" + finding.type().name() + "_REDACTED]");
                counts.merge(finding.type(), 1, Integer::sum);
                truncated = true;
            }
        }

        if (truncated) {
            log.warn("Vault capacity reached for session {}; some values were redacted irreversibly", sessionId);
        }

        return new SanitizationResult(out.toString(), counts, issued, truncated);
    }

    /**
     * Strips anything in the user's own input that is shaped like one of our placeholders.
     *
     * <p>Without this a caller can write {@code [EMAIL_ABCDEFGHIJKL]} directly into their
     * prompt. The model echoes it back, the re-injection stage sees a well-formed placeholder,
     * and the attacker has turned the response path into an oracle they can query about the
     * vault's contents. The lookup is session-scoped so nothing can actually be read out
     * across sessions, but the correct posture is to make user input and system control
     * syntax structurally unable to be confused — the same reason parameterised SQL exists
     * rather than careful quoting.
     */
    private String neutraliseTokenLookalikes(String text) {
        Matcher matcher = InMemoryTokenVault.TOKEN_PATTERN.matcher(text);
        if (!matcher.find()) {
            return text;
        }
        log.debug("Neutralised placeholder-shaped text in an inbound prompt");
        return matcher.reset().replaceAll("[REDACTED]");
    }

    /**
     * Greedy interval selection: sort by start, and on a tie prefer higher priority, then the
     * longer match. Anything overlapping an already-accepted span is dropped.
     */
    static List<PiiFinding> resolveOverlaps(List<PiiFinding> findings) {
        List<PiiFinding> sorted = new ArrayList<>(findings);
        sorted.sort(Comparator
                .comparingInt(PiiFinding::start)
                .thenComparing(Comparator.comparingInt(PiiFinding::priority).reversed())
                .thenComparing(Comparator.comparingInt(PiiFinding::length).reversed()));

        List<PiiFinding> accepted = new ArrayList<>();
        int furthestEnd = -1;

        for (PiiFinding candidate : sorted) {
            if (candidate.start() >= furthestEnd) {
                accepted.add(candidate);
                furthestEnd = candidate.end();
                continue;
            }
            // Overlaps the last accepted span. Replace it only if this candidate is strictly
            // better and starts no later, so a stronger detector still wins a contested span.
            PiiFinding last = accepted.get(accepted.size() - 1);
            if (candidate.priority() > last.priority() && candidate.start() <= last.start()) {
                accepted.set(accepted.size() - 1, candidate);
                furthestEnd = Math.max(furthestEnd, candidate.end());
            }
        }
        return accepted;
    }

    public int maxPromptLength() {
        return props.getMaxPromptLength();
    }
}
