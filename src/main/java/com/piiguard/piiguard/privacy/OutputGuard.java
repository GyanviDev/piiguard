package com.piiguard.piiguard.privacy;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;

/**
 * Guards the return path: restores placeholders to their real values, and inspects what the
 * model produced before any of it reaches the user.
 *
 * <h3>Why an outbound stage was needed at all</h3>
 *
 * <p>The original design protected the request and trusted the response completely. That is
 * half a proxy. Everything an attacker wants — the model's output — was passed through
 * unexamined, which leaves two real gaps:
 *
 * <ul>
 *   <li><b>Unbounded placeholder substitution.</b> Re-injection matched anything shaped like a
 *       token and replaced it with whatever the vault returned, falling back to the token text
 *       on a miss. Restoration is now explicitly scoped to placeholders this session actually
 *       issued, and anything else is reported rather than silently passed along.</li>
 *   <li><b>Model-generated sensitive data.</b> The model never sees real PII, so it cannot leak
 *       ours — but it can invent a plausible SSN, card number or email and present it as fact,
 *       and a user reading a privacy proxy's output will reasonably assume it was checked. It
 *       now is.</li>
 * </ul>
 *
 * <p>The framing that matters: input sanitisation controls what we disclose, output inspection
 * controls what we vouch for. Those are different problems and they need different stages.
 */
@Component
public class OutputGuard {

    private final RegexSanitizer regexSanitizer;

    public OutputGuard(RegexSanitizer regexSanitizer) {
        this.regexSanitizer = regexSanitizer;
    }

    /**
     * @param text                the response to show the user
     * @param tokensRestored      placeholders successfully mapped back to real values
     * @param unknownTokens       placeholder-shaped strings this session never issued
     * @param generatedPiiTypes   sensitive value types the model produced by itself
     */
    public record GuardedResponse(
            String text,
            int tokensRestored,
            List<String> unknownTokens,
            List<PiiEntityType> generatedPiiTypes) {

        public boolean isClean() {
            return unknownTokens.isEmpty() && generatedPiiTypes.isEmpty();
        }
    }

    public GuardedResponse process(String modelOutput, String sessionId, TokenVault vault) {
        if (modelOutput == null || modelOutput.isEmpty()) {
            return new GuardedResponse("", 0, List.of(), List.of());
        }

        // Inspect BEFORE restoration. Afterwards the text legitimately contains the user's own
        // PII, and every detector would fire on it — the finding would be true and useless.
        List<PiiEntityType> generated = regexSanitizer.detect(modelOutput).stream()
                .map(PiiFinding::type)
                .distinct()
                .toList();

        List<String> unknown = new ArrayList<>();
        Matcher matcher = InMemoryTokenVault.TOKEN_PATTERN.matcher(modelOutput);
        StringBuilder restored = new StringBuilder();
        int lastEnd = 0;
        int count = 0;

        while (matcher.find()) {
            String token = matcher.group();
            Optional<String> realValue = vault.detokenize(sessionId, token);

            restored.append(modelOutput, lastEnd, matcher.start());
            lastEnd = matcher.end();

            if (realValue.isPresent()) {
                restored.append(realValue.get());
                count++;
            } else {
                // A placeholder we never minted. Leaving the literal text in place is the
                // conservative choice: it discloses nothing and it is visible to the user,
                // rather than being erased and leaving a sentence that reads as though it
                // were complete.
                unknown.add(token);
                restored.append(token);
            }
        }
        restored.append(modelOutput, lastEnd, modelOutput.length());

        return new GuardedResponse(restored.toString(), count, List.copyOf(unknown), generated);
    }
}
