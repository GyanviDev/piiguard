package com.piiguard.piiguard;

import org.springframework.stereotype.Component;
import java.util.concurrent.ConcurrentHashMap;
import java.util.UUID;

@Component
public class TokenVault {

    // THE VAULT: "sessionId:TOKEN_1" → "Gyanvi"
    private final ConcurrentHashMap<String, String> vault = new ConcurrentHashMap<>();

    // Store a real value, get back a fake token
    public String storeAndTokenize(String sessionId, String entityType, String realValue) {
        String token = "[" + entityType + "_" + UUID.randomUUID().toString().substring(0, 4).toUpperCase() + "]";
        vault.put(sessionId + ":" + token, realValue);
        return token;
    }

    // Given a token, get back the real value
    public String detokenize(String sessionId, String token) {
        return vault.getOrDefault(sessionId + ":" + token, token);
    }

    // Clear vault when session ends
    public void clearSession(String sessionId) {
        vault.keySet().removeIf(key -> key.startsWith(sessionId + ":"));
    }
}