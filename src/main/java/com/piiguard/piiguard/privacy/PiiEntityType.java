package com.piiguard.piiguard.privacy;

/**
 * The classes of sensitive value the proxy recognises.
 *
 * <p>The label is not cosmetic. It is written into the placeholder the model sees
 * ({@code [EMAIL_QRZTBKMWLFDN]}), which is what lets the model reason about the sentence
 * at all: "send an invoice to {@code [EMAIL_…]} and copy {@code [NAME_…]}" is answerable,
 * whereas "send an invoice to {@code [REDACTED]} and copy {@code [REDACTED]}" is not.
 * Keeping the <em>type</em> while destroying the <em>value</em> is the whole trick.
 *
 * <p>{@link #severity()} drives policy: some values are merely identifying, others are
 * directly exploitable if they ever escape.
 */
public enum PiiEntityType {

    EMAIL(2),
    PHONE(2),
    NAME(2),
    IP(1),
    DOB(2),

    /** Government identifiers — irreplaceable, so the highest tier. */
    SSN(3),
    AADHAAR(3),
    PAN(3),
    PASSPORT(3),

    /** Financial instruments. */
    CARD(3),
    IBAN(3),
    IFSC(1),

    /**
     * Credentials found in a prompt: bearer tokens, API keys, private key blocks.
     * People paste these into chat assistants constantly while debugging, and unlike a
     * phone number a leaked key is immediately actionable by whoever receives it.
     */
    SECRET(3);

    private final int severity;

    PiiEntityType(int severity) {
        this.severity = severity;
    }

    /** 1 = contextual, 2 = identifying, 3 = critical. */
    public int severity() {
        return severity;
    }
}
