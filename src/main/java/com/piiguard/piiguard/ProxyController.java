package com.piiguard.piiguard;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ProxyController {

    @Autowired
    private TokenVault tokenVault;

    @Autowired
    private RegexSanitizer regexSanitizer;

    @Autowired
    private DifferentialPrivacyService dpService;

    @Autowired
    private NerService nerService;

    @Autowired
    private AdversarialHarnessService adversarialHarness;

    @Value("${groq.api.key:API_KEY}")
    private String groqApiKey;

    @PostMapping("/proxy")
    public ResponseEntity<Map<String, Object>> processPrompt(
            @RequestBody Map<String, String> request) {

        String userPrompt = request.get("prompt");
        String sessionId = UUID.randomUUID().toString();

        // Check for attacks before processing
        if (adversarialHarness.isAttack(userPrompt)) {
            Map<String, Object> blocked = new LinkedHashMap<>();
            blocked.put("originalPrompt", userPrompt);
            blocked.put("sanitizedPrompt", "BLOCKED");
            blocked.put("llmResponse", "Request blocked: adversarial attack detected.");
            blocked.put("sessionId", sessionId);
            blocked.put("attackDetected", true);
            return ResponseEntity.status(403).body(blocked);
        }

        // Layer 1: Regex sanitization (emails, phones, cards, IPs)
        String sanitized = regexSanitizer.sanitize(userPrompt, sessionId, tokenVault);

        // Layer 2: NER sanitization (person names)
        String nerSanitized = nerService.sanitizeNames(sanitized, sessionId, tokenVault);

        // Layer 3: Differential Privacy on numbers
        String dpApplied = dpService.applyDifferentialPrivacy(nerSanitized);

        String llmResponse = callGroq(dpApplied);
        String finalResponse = reInjectTokens(llmResponse, sessionId);
        tokenVault.clearSession(sessionId);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("originalPrompt", userPrompt);
        response.put("sanitizedPrompt", dpApplied);
        response.put("llmResponse", finalResponse);
        response.put("sessionId", sessionId);
        response.put("attackDetected", false);
        response.put("nerActive", nerService.isLoaded());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/attack")
    public ResponseEntity<List<Map<String, Object>>> runAttacks() {
        List<Map<String, Object>> results = adversarialHarness.runAllAttacks();
        return ResponseEntity.ok(results);
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("server", "running");
        status.put("nerModelLoaded", nerService.isLoaded());
        status.put("dpEpsilon", 0.1);
        status.put("attackPatternsLoaded", 5);
        return ResponseEntity.ok(status);
    }

    private String callGroq(String sanitizedPrompt) {
        try {
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(groqApiKey);

            Map<String, Object> body = new HashMap<>();
            body.put("model", "llama-3.3-70b-versatile");
            body.put("messages", List.of(
                Map.of("role", "system",
                       "content", "You are a helpful enterprise assistant."),
                Map.of("role", "user", "content", sanitizedPrompt)
            ));

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);
            ResponseEntity<Map> resp = restTemplate.postForEntity(
                "https://api.groq.com/openai/v1/chat/completions",
                entity, Map.class);

            List<Map> choices = (List<Map>) resp.getBody().get("choices");
            Map message = (Map) choices.get(0).get("message");
            return (String) message.get("content");

        } catch (Exception e) {
            return "LLM call failed: " + e.getMessage();
        }
    }

    private String reInjectTokens(String response, String sessionId) {
        java.util.regex.Pattern tokenPattern =
            java.util.regex.Pattern.compile("\\[[A-Z]+_[A-Z0-9]+\\]");
        java.util.regex.Matcher matcher = tokenPattern.matcher(response);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            String token = matcher.group();
            String realValue = tokenVault.detokenize(sessionId, token);
            matcher.appendReplacement(result,
                java.util.regex.Matcher.quoteReplacement(realValue));
        }
        matcher.appendTail(result);
        return result.toString();
    }
}