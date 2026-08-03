package com.piiguard.piiguard.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

/**
 * Outbound HTTP clients, each with explicit timeouts.
 *
 * <p>The original code did {@code new RestTemplate()} inline in two services. A default
 * {@code RestTemplate} has <em>no</em> connect or read timeout, so a slow or hung upstream
 * holds the calling Tomcat worker thread indefinitely. With the default pool of 200 threads,
 * 200 slow requests take the whole proxy down. Timeouts are the fix; separate beans exist
 * because the ML sidecar (must be fast, sits next to us) and the LLM (inherently slow,
 * lives across the internet) deserve very different budgets.
 */
@Configuration
public class HttpClientConfig {

    @Bean
    public RestTemplate llmRestTemplate(RestTemplateBuilder builder, PiiGuardProperties props) {
        return builder
                .connectTimeout(props.getLlm().getConnectTimeout())
                .readTimeout(props.getLlm().getReadTimeout())
                .build();
    }

    @Bean
    public RestTemplate mlRestTemplate(RestTemplateBuilder builder, PiiGuardProperties props) {
        return builder
                .connectTimeout(props.getDetection().getMlConnectTimeout())
                .readTimeout(props.getDetection().getMlReadTimeout())
                .build();
    }
}
