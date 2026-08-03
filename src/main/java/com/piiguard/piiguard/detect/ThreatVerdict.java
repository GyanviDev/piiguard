package com.piiguard.piiguard.detect;

/**
 * The single answer to "is this prompt an attack?".
 *
 * <p>The original code answered that question with two separate methods, {@code isAttack} and
 * {@code getDetectionMethod}, and the controller called both. Each call independently made an
 * HTTP round trip to the ML classifier, so every request paid the inference cost twice — and
 * worse, the two calls could disagree, because the model is called with the same input but its
 * result was interpreted under different rules in each method. Prompts were being blocked and
 * then recorded in the audit log as {@code detectionMethod = "NONE"}. An audit trail that
 * misstates why a request was refused is not an audit trail.
 *
 * <p>One evaluation, one verdict, one round trip.
 *
 * @param attack      whether to refuse the request
 * @param method      {@code ML}, {@code REGEX}, {@code ML+REGEX}, {@code NONE} or {@code UNAVAILABLE}
 * @param confidence  model probability where one was obtained, otherwise 0
 * @param rule        the specific rule or signal that fired, for the audit record
 */
public record ThreatVerdict(boolean attack, String method, double confidence, String rule) {

    public static ThreatVerdict safe() {
        return new ThreatVerdict(false, "NONE", 0.0, "none");
    }

    public static ThreatVerdict blocked(String method, double confidence, String rule) {
        return new ThreatVerdict(true, method, confidence, rule);
    }
}
