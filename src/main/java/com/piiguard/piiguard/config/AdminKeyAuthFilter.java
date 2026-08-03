package com.piiguard.piiguard.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/**
 * Authenticates operator requests with a shared secret supplied as {@code X-Admin-Key}.
 *
 * <p>Deliberately minimal: this is a single-tenant demo proxy, so a full OAuth2 resource
 * server would be ceremony without benefit. What matters is that the sensitive endpoints
 * are no longer anonymous. Two details are not optional:
 *
 * <ul>
 *   <li>The comparison uses {@link MessageDigest#isEqual} rather than {@code String.equals}.
 *       String comparison short-circuits at the first differing byte, so response latency
 *       leaks how many leading characters an attacker guessed correctly — a timing oracle
 *       that turns a brute-force from astronomically hard into linear in key length.</li>
 *   <li>A blank configured key authenticates nobody. Failing closed means a missed
 *       environment variable makes the admin API unavailable instead of public.</li>
 * </ul>
 */
public class AdminKeyAuthFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Admin-Key";
    public static final String ROLE = "ROLE_ADMIN";

    private final byte[] expectedKey;

    public AdminKeyAuthFilter(String adminApiKey) {
        this.expectedKey = adminApiKey == null ? new byte[0] : adminApiKey.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String presented = request.getHeader(HEADER);

        if (expectedKey.length > 0 && presented != null
                && MessageDigest.isEqual(expectedKey, presented.getBytes(StandardCharsets.UTF_8))) {

            var auth = new UsernamePasswordAuthenticationToken(
                    "admin", null, List.of(new SimpleGrantedAuthority(ROLE)));
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        try {
            chain.doFilter(request, response);
        } finally {
            // Thread-pooled containers reuse threads; leaving the context populated would
            // hand the next unauthenticated request an admin identity.
            SecurityContextHolder.clearContext();
        }
    }
}
