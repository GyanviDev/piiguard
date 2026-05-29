package com.piiguard.piiguard;

import org.springframework.stereotype.Component;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class RegexSanitizer {

    // Patterns to detect sensitive data
    private static final Pattern EMAIL = 
        Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    
    private static final Pattern PHONE = 
        Pattern.compile("\\b(\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b");
    
    private static final Pattern CREDIT_CARD = 
        Pattern.compile("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b");

    private static final Pattern IP_ADDRESS = 
        Pattern.compile("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b");

    public String sanitize(String text, String sessionId, TokenVault vault) {
        text = replacePattern(text, EMAIL, "EMAIL", sessionId, vault);
        text = replacePattern(text, PHONE, "PHONE", sessionId, vault);
        text = replacePattern(text, CREDIT_CARD, "CARD", sessionId, vault);
        text = replacePattern(text, IP_ADDRESS, "IP", sessionId, vault);
        return text;
    }

    private String replacePattern(String text, Pattern pattern, 
                                   String entityType, String sessionId, 
                                   TokenVault vault) {
        Matcher matcher = pattern.matcher(text);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            String realValue = matcher.group();
            String token = vault.storeAndTokenize(sessionId, entityType, realValue);
            matcher.appendReplacement(result, Matcher.quoteReplacement(token));
        }
        matcher.appendTail(result);
        return result.toString();
    }
}