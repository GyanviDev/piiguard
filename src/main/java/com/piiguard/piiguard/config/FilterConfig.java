package com.piiguard.piiguard.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Registers the rate limiter ahead of the security chain so that abusive traffic is rejected
 * before any expensive work — parsing, authentication, model inference — is done on its behalf.
 * A limiter that runs after the work it is meant to prevent is decoration.
 */
@Configuration
public class FilterConfig {

    private final RateLimitFilter rateLimitFilter;
    private final boolean enabled;

    public FilterConfig(PiiGuardProperties props) {
        this.enabled = props.getRateLimit().isEnabled();
        this.rateLimitFilter = new RateLimitFilter(props.getRateLimit());
    }

    @Bean
    public FilterRegistrationBean<RateLimitFilter> rateLimitRegistration() {
        FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>(rateLimitFilter);
        registration.addUrlPatterns("/api/proxy");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.setEnabled(enabled);
        return registration;
    }

    /** Keeps the bucket map bounded when clients come and go. */
    @Scheduled(fixedDelay = 600_000L)
    public void evictIdleBuckets() {
        rateLimitFilter.evictIdle(600_000L);
    }
}
