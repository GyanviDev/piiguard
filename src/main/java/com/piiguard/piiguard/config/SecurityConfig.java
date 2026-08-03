package com.piiguard.piiguard.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * The access-control model.
 *
 * <p>Before this class existed the application had no security layer at all, which meant
 * {@code GET /api/audit} returned every prompt any user had ever submitted — including the
 * raw, unredacted text — to any anonymous caller on the internet. That was the single most
 * severe defect in the project: a privacy product with a public transcript endpoint.
 *
 * <p>The rules now are:
 * <ul>
 *   <li><b>Public</b> — the UI, {@code POST /api/proxy}, {@code GET /api/health}, and the
 *       actuator health probe. These are the product.</li>
 *   <li><b>Admin only</b> — {@code /api/audit}, {@code /api/attack}, {@code /api/status} and
 *       the remaining actuator endpoints. Audit records are evidence, attack payloads are a
 *       working exploit catalogue, and metrics disclose traffic volume.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final PiiGuardProperties props;

    public SecurityConfig(PiiGuardProperties props) {
        this.props = props;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CSRF protection defends against the browser silently attaching ambient
            // credentials (cookies) to a cross-site request. This API is stateless and
            // carries no cookie or session, so there is no ambient authority to abuse and
            // the token exchange would only add friction. Disabling it here is a reasoned
            // decision, not an oversight — it would be wrong the moment we add cookie auth.
            .csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/index.html", "/js/**", "/css/**", "/favicon.ico").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/proxy").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/health").permitAll()
                .requestMatchers("/actuator/health/**", "/actuator/info").permitAll()
                .requestMatchers("/api/audit/**", "/api/attack", "/api/status", "/actuator/**")
                    .hasAuthority(AdminKeyAuthFilter.ROLE)
                .anyRequest().denyAll()
            )

            .addFilterBefore(new AdminKeyAuthFilter(props.getAdminApiKey()),
                             UsernamePasswordAuthenticationFilter.class)

            // No browser login prompt for an API — return status codes as data.
            .httpBasic(b -> b.disable())
            .formLogin(f -> f.disable())

            // Without this, Spring's default handling answers an anonymous request to a
            // protected route with 403. That is the wrong signal: 403 means "we know who you
            // are and you may not do this", so a client reads it as final and does not retry
            // with credentials. 401 means "authenticate and try again", which is both true
            // here and actionable. The distinction matters for anything scripted against
            // this API, and getting it wrong is a small correctness bug that surfaces as a
            // confusing support ticket rather than an error.
            .exceptionHandling(handling -> handling
                .authenticationEntryPoint((request, response, exception) -> {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write(
                        "{\"error\":\"Authentication required\",\"status\":\"UNAUTHORIZED\"}");
                })
            )

            .headers(h -> h
                .frameOptions(f -> f.deny())
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    // Locked down enough to be meaningful: no third-party script or style
                    // origins, no framing, no form posts, no base-tag hijacking. The UI was
                    // refactored to external JS specifically so 'unsafe-inline' could be
                    // dropped from script-src.
                    "default-src 'self'; " +
                    "script-src 'self'; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "img-src 'self' data:; " +
                    "font-src 'self'; " +
                    "connect-src 'self'; " +
                    "frame-ancestors 'none'; " +
                    "base-uri 'none'; " +
                    "form-action 'none'"))
                .referrerPolicy(r -> r.policy(
                    org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
                        .ReferrerPolicy.NO_REFERRER))
            );

        return http.build();
    }

    /**
     * The previous {@code @CrossOrigin(origins = "http://localhost:8081")} annotation was
     * both useless and wrong: the UI is served from the same origin as the API, so no
     * preflight ever occurs, and the hard-coded localhost value would have been incorrect
     * in the deployed environment. Same-origin only, with the allowed origin list under
     * configuration if a separate front end is ever deployed.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of());
        config.setAllowedMethods(List.of("GET", "POST"));
        config.setAllowedHeaders(List.of("Content-Type", AdminKeyAuthFilter.HEADER));
        config.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
