package com.piiguard.piiguard.privacy;

import com.piiguard.piiguard.config.PiiGuardProperties;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Adds Laplace-distributed noise to numeric literals so that magnitudes reaching the model
 * are approximate rather than exact.
 *
 * <h3>An honest statement of what this does and does not guarantee</h3>
 *
 * <p>The README previously claimed formal (ε,δ)-differential privacy. That claim does not
 * survive contact with the definition, and it is better to correct it here than to have it
 * dismantled in a design review. Differential privacy is a property of a <em>randomised query
 * over a dataset</em>: it bounds how much the output can change when one individual's record
 * is added or removed. This code perturbs literal numbers inside a sentence. There is no
 * dataset, no query, and no notion of an adjacent dataset, so there is no ε to be private with
 * respect to. Two further gaps are worth naming out loud:
 *
 * <ul>
 *   <li><b>Composition.</b> Send the same prompt ten times and average the answers and the
 *       noise cancels; the true value emerges. Real DP systems answer this with a budget that
 *       is spent and never refilled, which is why {@link PrivacyBudgetAccountant} exists.</li>
 *   <li><b>Correlation.</b> Perturbing revenue, cost and profit independently breaks the
 *       arithmetic between them, and an analyst who knows profit = revenue − cost can solve
 *       back towards the originals.</li>
 * </ul>
 *
 * <p>So the accurate description is: <em>the Laplace mechanism applied to numeric literals,
 * giving calibrated magnitude obfuscation with a budget accountant, not a formal DP guarantee
 * over a dataset.</em> It is genuinely useful — an approximate revenue figure is enough for the
 * model to reason with and not enough to be worth exfiltrating — and it is now described as
 * what it is.
 *
 * <h3>Defects fixed</h3>
 *
 * <p><b>It corrupted every number in the prompt.</b> With ε=0.1 and sensitivity 1 the noise
 * scale was 10, applied to <em>all</em> digits. "Take 2 tablets twice daily" became
 * "Take -7.34 tablets 9.21 daily"; every year, quantity, dosage and version number was
 * destroyed. Noise now scales with the magnitude of the value, skips anything below a
 * configured floor, and leaves four-digit years alone — so a revenue figure is obscured and a
 * dosage is not.
 *
 * <p><b>The randomness was predictable.</b> {@link java.util.Random} is a 48-bit linear
 * congruential generator; observing a few outputs reveals its internal state and therefore
 * every past and future sample. An adversary who can recover the noise can subtract it and
 * recover the original values, which defeats the mechanism completely.
 * {@link SecureRandom} is not optional for anything whose security depends on unpredictability.
 *
 * <p><b>The sampler could emit infinity.</b> {@code -scale * signum(u) * ln(1 - 2|u|)} with
 * {@code u} drawn from {@code nextDouble() - 0.5} admits exactly {@code u = -0.5}, giving
 * {@code ln(0) = -∞}. The formatted output became the literal string "-Infinity", corrupting
 * the prompt. Rare, non-deterministic, and impossible to debug after the fact — the kind of
 * bug worth closing the moment it is noticed.
 */
@Component
public class DifferentialPrivacyService {

    /**
     * Matches a number, optionally with thousands separators and a decimal part. The leading
     * {@code (?<![\w.])} guard stops it firing on digits that are already part of something
     * else — a version string, or an identifier. Token placeholders are structurally immune
     * because their bodies contain no digits at all (see {@link InMemoryTokenVault}).
     */
    private static final Pattern NUMBER = Pattern.compile("(?<![\\w.])-?\\d{1,3}(?:,\\d{3})+(?:\\.\\d+)?(?![\\w])|(?<![\\w.])-?\\d+(?:\\.\\d+)?(?![\\w])");

    private final SecureRandom random = new SecureRandom();
    private final PiiGuardProperties.Dp config;

    public DifferentialPrivacyService(PiiGuardProperties props) {
        this.config = props.getDp();
    }

    /**
     * @param text          the perturbed text
     * @param valuesNoised  how many literals were actually changed
     * @param epsilonSpent  budget consumed, by sequential composition: ε per perturbed value
     */
    public record DpResult(String text, int valuesNoised, double epsilonSpent) {
        public static DpResult unchanged(String text) {
            return new DpResult(text, 0, 0.0);
        }
    }

    public DpResult apply(String text) {
        if (!config.isEnabled()) {
            return DpResult.unchanged(text);
        }

        Matcher matcher = NUMBER.matcher(text);
        StringBuilder result = new StringBuilder();
        int noised = 0;
        int lastEnd = 0;

        while (matcher.find()) {
            String literal = matcher.group();
            String replacement = perturb(literal);

            result.append(text, lastEnd, matcher.start()).append(replacement);
            lastEnd = matcher.end();

            if (!replacement.equals(literal)) {
                noised++;
            }
        }
        result.append(text, lastEnd, text.length());

        // Sequential composition: independent mechanisms on the same input add their epsilons.
        return new DpResult(result.toString(), noised, noised * config.getEpsilon());
    }

    private String perturb(String literal) {
        double value;
        try {
            value = Double.parseDouble(literal.replace(",", ""));
        } catch (NumberFormatException e) {
            return literal;
        }

        if (!shouldPerturb(literal, value)) {
            return literal;
        }

        // Noise proportional to magnitude, floored so small-but-eligible values still move.
        double sensitivity = Math.max(
                config.getAbsoluteSensitivity(),
                Math.abs(value) * config.getRelativeSensitivity());
        double noisy = value + sampleLaplace(sensitivity / config.getEpsilon());

        boolean wasInteger = !literal.contains(".");
        if (wasInteger) {
            return String.valueOf(Math.round(noisy));
        }
        return BigDecimal.valueOf(noisy).setScale(2, RoundingMode.HALF_UP).toPlainString();
    }

    private boolean shouldPerturb(String literal, double value) {
        // Small numbers carry categorical meaning — counts, dosages, ratings, ranks — that
        // noise turns into nonsense while protecting nothing an attacker wanted.
        if (Math.abs(value) < config.getMinMagnitude()) {
            return false;
        }
        // A bare four-digit number in the plausible year range is a date, not a statistic.
        if (literal.length() == 4 && !literal.contains(".") && !literal.contains(",")) {
            int asInt = (int) value;
            if (asInt >= config.getYearFloor() && asInt <= config.getYearCeiling()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Inverse-transform sampling from Laplace(0, b).
     *
     * <p>{@code u} is drawn from the open interval (-0.5, 0.5) rather than the half-open
     * interval the old code used, which is what removes the {@code ln(0) = -∞} case. The
     * resample loop is the clearest way to state that intent.
     */
    private double sampleLaplace(double scale) {
        double u;
        do {
            u = random.nextDouble() - 0.5;
        } while (u <= -0.5 || u >= 0.5 || Math.abs(u) == 0.5);

        return -scale * Math.signum(u) * Math.log(1 - 2 * Math.abs(u));
    }

    public double epsilon() {
        return config.getEpsilon();
    }

    public boolean isEnabled() {
        return config.isEnabled();
    }
}
