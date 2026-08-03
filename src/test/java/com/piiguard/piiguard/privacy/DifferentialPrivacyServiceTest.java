package com.piiguard.piiguard.privacy;

import com.piiguard.piiguard.config.PiiGuardProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DifferentialPrivacyServiceTest {

    private PiiGuardProperties props;
    private DifferentialPrivacyService dp;

    @BeforeEach
    void setUp() {
        props = new PiiGuardProperties();
        dp = new DifferentialPrivacyService(props);
    }

    @Test
    @DisplayName("large values are perturbed")
    void perturbsLargeValues() {
        DifferentialPrivacyService.DpResult result = dp.apply("Revenue was 4500000 last quarter");

        assertEquals(1, result.valuesNoised());
        assertFalse(result.text().contains("4500000"), "The exact figure must not survive");
        assertTrue(result.epsilonSpent() > 0);
    }

    @Test
    @DisplayName("small values are left alone — this is the bug that made the feature unusable")
    void doesNotDestroySmallNumbers() {
        // With the old fixed sensitivity of 1.0 and epsilon 0.1 the noise scale was 10 on
        // EVERY number, so "take 2 tablets twice daily" came out as something like
        // "take -7.34 tablets 9.21 daily" and the answer was worthless.
        String input = "Take 2 tablets twice daily for 10 days";
        DifferentialPrivacyService.DpResult result = dp.apply(input);

        assertEquals(input, result.text());
        assertEquals(0, result.valuesNoised());
    }

    @Test
    @DisplayName("years are recognised as dates, not statistics")
    void preservesYears() {
        String input = "The contract was signed in 2019 and renewed in 2024";
        assertEquals(input, dp.apply(input).text());
    }

    @Test
    @DisplayName("text with no numbers is returned unchanged")
    void leavesProseAlone() {
        String input = "What should I eat for breakfast?";
        assertEquals(input, dp.apply(input).text());
    }

    @Test
    @DisplayName("noise never produces Infinity or NaN")
    void neverEmitsInfinity() {
        // The old sampler could draw u = -0.5 exactly, giving ln(0) = -Infinity, and the
        // formatted output became the literal string "-Infinity" inside the prompt.
        for (int i = 0; i < 20_000; i++) {
            String out = dp.apply("Total 5000000 units").text();
            assertFalse(out.contains("Infinity"), "Produced Infinity on iteration " + i);
            assertFalse(out.contains("NaN"), "Produced NaN on iteration " + i);
        }
    }

    @Test
    @DisplayName("noise is proportional to magnitude, so large values stay usefully large")
    void noiseScalesWithMagnitude() {
        // A fixed noise scale either destroys small values or fails to obscure large ones.
        // Perturbing 10,000,000 must not routinely change its order of magnitude.
        long value = 10_000_000L;
        int wildlyWrong = 0;

        for (int i = 0; i < 500; i++) {
            String out = dp.apply("Revenue " + value).text();
            long noisy = Long.parseLong(out.replaceAll("[^0-9-]", ""));
            if (Math.abs(noisy - value) > value) {
                wildlyWrong++;
            }
        }

        assertTrue(wildlyWrong < 25,
                "Noise changed the order of magnitude " + wildlyWrong + "/500 times");
    }

    @Test
    @DisplayName("integers stay integers")
    void preservesIntegerFormatting() {
        String out = dp.apply("Headcount 25000").text();
        assertFalse(out.contains("."), "An integer must not gain a decimal point: " + out);
    }

    @Test
    @DisplayName("successive runs differ — the mechanism is actually random")
    void isRandomised() {
        String first = dp.apply("Revenue 4500000").text();
        boolean anyDifferent = false;
        for (int i = 0; i < 20 && !anyDifferent; i++) {
            anyDifferent = !dp.apply("Revenue 4500000").text().equals(first);
        }
        assertTrue(anyDifferent, "Every sample was identical — the noise source is not working");
    }

    @Test
    @DisplayName("placeholders survive the noise stage untouched")
    void doesNotCorruptPlaceholders() {
        // Guaranteed structurally: token bodies are letters only, so no numeric pattern can
        // match inside one. Asserted here because the guarantee is easy to break by accident.
        String input = "Send [EMAIL_QRZTBKMWLFDN] the figure 8000000 for [NAME_ABCDEFGHIJKL]";
        String out = dp.apply(input).text();

        assertTrue(out.contains("[EMAIL_QRZTBKMWLFDN]"));
        assertTrue(out.contains("[NAME_ABCDEFGHIJKL]"));
        assertFalse(out.contains("8000000"));
    }

    @Test
    @DisplayName("disabling the feature disables it completely")
    void respectsTheKillSwitch() {
        props.getDp().setEnabled(false);
        String input = "Revenue was 4500000";

        DifferentialPrivacyService.DpResult result = dp.apply(input);
        assertEquals(input, result.text());
        assertEquals(0.0, result.epsilonSpent());
    }

    @Test
    @DisplayName("epsilon is charged per perturbed value, matching sequential composition")
    void chargesEpsilonPerValue() {
        props.getDp().setEpsilon(0.5);
        DifferentialPrivacyService.DpResult result = dp.apply("A 5000000 B 7000000 C 9000000");

        assertEquals(3, result.valuesNoised());
        assertEquals(1.5, result.epsilonSpent(), 1e-9);
    }

    @Test
    @DisplayName("comma-grouped numbers are handled as one value, not three")
    void handlesThousandsSeparators() {
        DifferentialPrivacyService.DpResult result = dp.apply("Revenue was 4,500,000 this year");

        assertEquals(1, result.valuesNoised());
        assertNotEquals("Revenue was 4,500,000 this year", result.text());
    }
}
