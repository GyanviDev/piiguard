package com.piiguard.piiguard;

import org.springframework.stereotype.Component;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class DifferentialPrivacyService {

    // Epsilon: privacy budget. Lower = more private, more noise.
    // 0.1 = strong privacy (used in healthcare/finance)
    private static final double EPSILON = 0.1;
    private static final double SENSITIVITY = 1.0;
    private final Random random = new Random();

    // Finds all numbers in text and adds Laplace noise to them
    public String applyDifferentialPrivacy(String text) {
        Pattern numberPattern = Pattern.compile("\\b\\d+(\\.\\d+)?\\b");
        Matcher matcher = numberPattern.matcher(text);
        StringBuffer result = new StringBuffer();

        while (matcher.find()) {
            double originalValue = Double.parseDouble(matcher.group());
            double noisyValue = originalValue + laplaceSample(SENSITIVITY / EPSILON);
            // Round to 2 decimal places
            String replacement = String.format("%.2f", noisyValue);
            matcher.appendReplacement(result, replacement);
        }
        matcher.appendTail(result);
        return result.toString();
    }

    // The Laplace mechanism: draws noise from Laplace distribution
    // Formula: -b * sign(u) * ln(1 - 2|u|) where b = sensitivity/epsilon
    private double laplaceSample(double scale) {
        double u = random.nextDouble() - 0.5;
        return -scale * Math.signum(u) * Math.log(1 - 2 * Math.abs(u));
    }
}