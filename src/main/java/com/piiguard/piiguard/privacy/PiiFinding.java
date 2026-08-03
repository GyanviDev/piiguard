package com.piiguard.piiguard.privacy;

/**
 * One detected sensitive value, located by character offset in the original text.
 *
 * <p>Offsets matter. The original implementation redacted by running each regex over the
 * whole string in sequence and, for names, by calling {@code text.indexOf(name)} — which
 * finds the <em>first</em> occurrence of that name anywhere, not the occurrence the detector
 * actually matched. Two bugs followed directly: a name appearing twice had the wrong instance
 * replaced, and a name whose reconstructed spelling differed from the source (a tokeniser
 * turns {@code O'Brien} into {@code O ' Brien}) returned {@code -1} and was left in the
 * prompt <em>after</em> a token had already been minted for it. That is the worst possible
 * outcome for a redaction system: it reports success and forwards the name to the model.
 *
 * <p>Carrying spans instead of doing in-place string surgery makes findings from every
 * detector comparable, lets overlaps be resolved deliberately, and reduces rewriting to a
 * single right-to-left pass that cannot invalidate its own indices.
 *
 * @param start     inclusive character offset
 * @param end       exclusive character offset
 * @param type      what kind of value this is
 * @param value     the matched text
 * @param detector  which detector claimed it — recorded so audit and metrics can tell
 *                  regex hits from model hits without guessing
 * @param priority  higher wins when two detectors claim overlapping text
 */
public record PiiFinding(
        int start,
        int end,
        PiiEntityType type,
        String value,
        String detector,
        int priority) {

    public int length() {
        return end - start;
    }

    public boolean overlaps(PiiFinding other) {
        return start < other.end && other.start < end;
    }
}
