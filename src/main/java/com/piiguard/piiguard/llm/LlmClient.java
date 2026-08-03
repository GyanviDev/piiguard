package com.piiguard.piiguard.llm;

import com.piiguard.piiguard.config.PiiGuardProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

/**
 * Calls the upstream model.
 *
 * <h3>Errors were being returned as answers</h3>
 *
 * <p>The original method caught every exception and returned {@code "LLM call failed: " +
 * e.getMessage()} as a {@code String} — which the controller then put in the {@code llmResponse}
 * field of a {@code 200 OK} response, ran through token re-injection, and rendered in the UI as
 * though the model had said it. Three things go wrong at once:
 *
 * <ul>
 *   <li>A caller cannot distinguish an outage from an answer. Every client-side retry,
 *       alert and dashboard built on this API would be wrong.</li>
 *   <li>Raw exception messages reach the browser. {@code RestClientException} messages routinely
 *       carry the request URL, upstream error bodies and occasionally credential fragments —
 *       an information disclosure handed straight to whoever triggered it.</li>
 *   <li>The failure string went through re-injection, so a message containing anything shaped
 *       like a placeholder would have had vault contents substituted into it.</li>
 * </ul>
 *
 * <p>Failures are now a typed exception. Detail goes to the log where operators can see it;
 * the client gets a status code and a message that says what happened and nothing more.
 *
 * <h3>Configuration failure is detected at startup, not per request</h3>
 *
 * <p>The API key defaulted to the literal string {@code "API_KEY"}, so a deployment with the
 * environment variable missing started cleanly and then failed on every request with a 401
 * from Groq rendered as an LLM answer. {@link #isConfigured()} makes the state visible on the
 * health endpoint, and an unconfigured proxy says so directly.
 */
@Component
public class LlmClient {

    private static final Logger log = LoggerFactory.getLogger(LlmClient.class);

    /**
     * Defence in depth. The prompt has already been redacted, but the model is also told
     * explicitly that bracketed placeholders are opaque. It costs nothing and it closes the
     * gap where a model helpfully "guesses" what a placeholder stood for and states the guess
     * as fact. This is a mitigation, not a control — instructions to a model are advisory, and
     * the actual guarantee comes from the fact that it never received the real values.
     */
    private static final String SYSTEM_PROMPT = """
            You are a helpful enterprise assistant.
            Text in square brackets such as [NAME_ABCDEFGH] or [EMAIL_IJKLMNOP] is a privacy \
            placeholder standing in for information you are not permitted to see. Treat each \
            placeholder as an opaque identifier: reason about it, refer to it by exactly the \
            text given, and never guess, invent or ask for the value behind it. Numeric values \
            may be approximate.""";

    private final RestTemplate restTemplate;
    private final PiiGuardProperties.Llm config;

    public LlmClient(@Qualifier("llmRestTemplate") RestTemplate restTemplate, PiiGuardProperties props) {
        this.restTemplate = restTemplate;
        this.config = props.getLlm();
    }

    /** Thrown when the upstream model cannot answer. Carries no upstream detail by design. */
    public static class LlmUnavailableException extends RuntimeException {
        public LlmUnavailableException(String message) {
            super(message);
        }
    }

    public String complete(String sanitizedPrompt) {
        if (!isConfigured()) {
            throw new LlmUnavailableException(
                    "Upstream model is not configured. Set the GROQ_API_KEY environment variable.");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(config.getApiKey());

            Map<String, Object> body = Map.of(
                    "model", config.getModel(),
                    "messages", List.of(
                            Map.of("role", "system", "content", SYSTEM_PROMPT),
                            Map.of("role", "user", "content", sanitizedPrompt)));

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    config.getBaseUrl(), new HttpEntity<>(body, headers), Map.class);

            return extractContent(response.getBody());

        } catch (RestClientException e) {
            // Full detail to the operator, nothing to the caller.
            log.error("Upstream model call failed: {}", e.toString());
            throw new LlmUnavailableException("The upstream model is unavailable. Please retry.");
        }
    }

    /**
     * Navigates the response defensively. The old code cast through raw {@code Map} and
     * {@code List} and read {@code choices[0].message.content} with no null checks, so a
     * moderation refusal or a rate-limit body — both of which omit {@code choices} — produced a
     * {@link NullPointerException} that surfaced as a 500 with a stack trace.
     */
    @SuppressWarnings("unchecked")
    private String extractContent(Map<String, Object> body) {
        if (body == null) {
            throw new LlmUnavailableException("The upstream model returned an empty response.");
        }
        Object choices = body.get("choices");
        if (!(choices instanceof List<?> choiceList) || choiceList.isEmpty()) {
            throw new LlmUnavailableException("The upstream model returned no completion.");
        }
        if (!(choiceList.get(0) instanceof Map<?, ?> firstChoice)
                || !(firstChoice.get("message") instanceof Map<?, ?> message)
                || !(message.get("content") instanceof String content)) {
            throw new LlmUnavailableException("The upstream model returned an unrecognised response.");
        }
        return content;
    }

    /** {@code "API_KEY"} was the old placeholder default and must not count as configured. */
    public boolean isConfigured() {
        String key = config.getApiKey();
        return key != null && !key.isBlank() && !"API_KEY".equals(key);
    }

    public String model() {
        return config.getModel();
    }
}
