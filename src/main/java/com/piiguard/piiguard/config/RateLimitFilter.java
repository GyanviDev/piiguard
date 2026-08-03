package com.piiguard.piiguard.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-client token bucket in front of {@code /api/proxy}.
 *
 * <p>Every proxied prompt spends real money and a finite third-party quota (Groq's free tier
 * is 14,400 requests/day) and pins a worker thread for as long as the model takes to answer.
 * Without a limiter, one script exhausts the day's quota in minutes and denies service to
 * everyone else — the cheapest possible attack on the system, needing no exploit at all.
 *
 * <p>Token bucket rather than a fixed window because a fixed window lets a caller fire the
 * whole allowance in the last second of one window and again in the first second of the next,
 * yielding twice the intended peak rate. A bucket refills continuously, so the sustained rate
 * holds while short, legitimate bursts still succeed.
 *
 * <p>This is deliberately in-process. It is the correct scope for a single instance and it is
 * honest about its limit: behind more than one replica the effective ceiling multiplies by the
 * replica count, and the fix is a shared counter in Redis, not a bigger map.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private final double refillPerSecond;
    private final double capacity;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitFilter(PiiGuardProperties.RateLimit config) {
        this.refillPerSecond = config.getRequestsPerMinute() / 60.0;
        this.capacity = config.getBurst();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String client = clientKey(request);

        if (!buckets.computeIfAbsent(client, k -> new Bucket(capacity)).tryConsume()) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setHeader("Retry-After", "60");
            response.getWriter().write(
                "{\"error\":\"Rate limit exceeded\",\"status\":\"TOO_MANY_REQUESTS\"}");
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * Behind a reverse proxy (Render, nginx, an ALB) every request arrives from the proxy's
     * own address, so keying on {@code getRemoteAddr} alone would put all users in one bucket.
     * Only the first hop of X-Forwarded-For is used, and only the leftmost entry — the rest of
     * that header is attacker-controlled and must never be trusted.
     */
    private String clientKey(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            String first = (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
            if (!first.isEmpty() && first.length() <= 45) {
                return first;
            }
        }
        return request.getRemoteAddr();
    }

    /** Evicts idle buckets so a stream of unique source addresses cannot grow the map forever. */
    public void evictIdle(long idleMillis) {
        long cutoff = System.currentTimeMillis() - idleMillis;
        buckets.entrySet().removeIf(e -> e.getValue().lastAccess() < cutoff);
    }

    private final class Bucket {
        private double tokens;
        private long lastRefillNanos;
        private volatile long lastAccessMillis;

        Bucket(double initial) {
            this.tokens = initial;
            this.lastRefillNanos = System.nanoTime();
            this.lastAccessMillis = System.currentTimeMillis();
        }

        synchronized boolean tryConsume() {
            long now = System.nanoTime();
            double elapsedSeconds = (now - lastRefillNanos) / 1_000_000_000.0;
            lastRefillNanos = now;
            lastAccessMillis = System.currentTimeMillis();

            tokens = Math.min(capacity, tokens + elapsedSeconds * refillPerSecond);
            if (tokens < 1.0) {
                return false;
            }
            tokens -= 1.0;
            return true;
        }

        long lastAccess() {
            return lastAccessMillis;
        }
    }
}
