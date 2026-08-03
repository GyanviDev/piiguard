package com.piiguard.piiguard.privacy;

import com.piiguard.piiguard.config.PiiGuardProperties;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks how much privacy budget each caller has spent, and refuses to spend more once the
 * allowance is gone.
 *
 * <h3>Why a mechanism without this is not a privacy control</h3>
 *
 * <p>Noise is only protective while it is unknown. Ask the same question with the same
 * underlying value <i>n</i> times and average the answers, and the noise shrinks as 1/√n —
 * after a few hundred repetitions the attacker has recovered the original figure to several
 * significant digits. The original implementation had no defence against this at all: every
 * request drew fresh noise, and repeating a prompt was free.
 *
 * <p>Sequential composition is the formal statement of the problem: <i>k</i> queries each
 * satisfying ε-DP together satisfy only (kε)-DP, and privacy degrades linearly with use. The
 * standard answer is a budget that is spent and never refilled. That is what this class is.
 *
 * <p>Two limitations, stated rather than hidden. Budget is keyed by caller identity, so two
 * clients colluding get two budgets — the honest fix is to key by <em>data subject</em>, which
 * needs an identity model this project does not have. And the budget is in memory, so it
 * resets on deploy and does not span replicas; that is a Redis-shaped problem, the same one
 * the token vault has.
 */
@Component
public class PrivacyBudgetAccountant {

    private final Map<String, Ledger> ledgers = new ConcurrentHashMap<>();
    private final PiiGuardProperties.Dp config;

    public PrivacyBudgetAccountant(PiiGuardProperties props) {
        this.config = props.getDp();
    }

    /** @param allowed false when the request would overspend; the caller must skip noising */
    public record BudgetDecision(boolean allowed, double spent, double remaining) {}

    /** Non-committal check used to decide whether to run the mechanism at all. */
    public BudgetDecision check(String subject) {
        Ledger ledger = ledgers.computeIfAbsent(subject, k -> new Ledger());
        synchronized (ledger) {
            ledger.lastAccess = Instant.now();
            double remaining = config.getSessionBudget() - ledger.spent;
            return new BudgetDecision(remaining > 0, ledger.spent, Math.max(0, remaining));
        }
    }

    /** Records budget actually consumed. Called after the mechanism runs, with the real cost. */
    public BudgetDecision charge(String subject, double epsilon) {
        Ledger ledger = ledgers.computeIfAbsent(subject, k -> new Ledger());
        synchronized (ledger) {
            ledger.spent += epsilon;
            ledger.lastAccess = Instant.now();
            double remaining = config.getSessionBudget() - ledger.spent;
            return new BudgetDecision(remaining > 0, ledger.spent, Math.max(0, remaining));
        }
    }

    /**
     * Budget windows reset after a long idle period. This is a pragmatic compromise, not a
     * theoretical one: a permanent budget is the strict reading, but it makes a demo unusable
     * after a few dozen requests, and a compromise you have named is better than one you have
     * not noticed.
     */
    @Scheduled(fixedDelay = 3_600_000L)
    public void resetIdleLedgers() {
        Instant cutoff = Instant.now().minus(Duration.ofHours(24));
        ledgers.entrySet().removeIf(e -> e.getValue().lastAccess.isBefore(cutoff));
    }

    public double totalBudget() {
        return config.getSessionBudget();
    }

    private static final class Ledger {
        double spent;
        Instant lastAccess = Instant.now();
    }
}
