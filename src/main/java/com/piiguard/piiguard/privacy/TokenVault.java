package com.piiguard.piiguard.privacy;

import java.util.Optional;

/**
 * Two-way map between a real sensitive value and the placeholder that stands in for it.
 *
 * <p>This is an interface rather than a class for a concrete reason: the in-process
 * implementation is correct for exactly one replica. The moment the proxy is scaled
 * horizontally, request N+1 can land on a different instance from request N and the
 * placeholders become undecodable. Swapping in a Redis-backed implementation is then a
 * one-bean change instead of a rewrite, and the tests that pin the contract keep working.
 */
public interface TokenVault {

    /**
     * Returns the placeholder for {@code realValue}, creating one if this session has not
     * seen the value before. Repeating a value within a session must return the same
     * placeholder, so that "Priya emailed Priya's manager" survives with its coreference
     * intact instead of becoming two apparently unrelated people.
     *
     * @throws VaultCapacityException when the session or the vault is at its configured limit
     */
    String tokenize(String sessionId, PiiEntityType type, String realValue);

    /** Empty when the placeholder was never issued for this session. */
    Optional<String> detokenize(String sessionId, String token);

    /** Destroys every secret held for the session. Must be safe to call more than once. */
    void clearSession(String sessionId);

    /** Number of sessions currently holding plaintext. Exposed for metrics and tests. */
    int activeSessions();

    /** Thrown instead of silently dropping data when a limit is hit. */
    class VaultCapacityException extends RuntimeException {
        public VaultCapacityException(String message) {
            super(message);
        }
    }
}
