package com.piiguard.piiguard;

import opennlp.tools.namefind.NameFinderME;
import opennlp.tools.namefind.TokenNameFinderModel;
import opennlp.tools.tokenize.SimpleTokenizer;
import opennlp.tools.util.Span;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.util.logging.Logger;

@Component
public class NerService {

    private static final Logger log = Logger.getLogger(NerService.class.getName());
    private NameFinderME personFinder;
    private boolean modelLoaded = false;

    @PostConstruct
    public void loadModel() {
        try {
            InputStream modelStream = getClass()
                .getClassLoader()
                .getResourceAsStream("en-ner-person.bin");

            if (modelStream == null) {
                log.warning("NER model not found — falling back to regex only");
                return;
            }

            TokenNameFinderModel model = new TokenNameFinderModel(modelStream);
            personFinder = new NameFinderME(model);
            modelLoaded = true;
            log.info("NER person model loaded successfully");

        } catch (Exception e) {
            log.warning("NER model failed to load: " + e.getMessage());
        }
    }

    public String sanitizeNames(String text, String sessionId, TokenVault vault) {
        if (!modelLoaded || personFinder == null) {
            return text; // graceful fallback to regex only
        }

        try {
            SimpleTokenizer tokenizer = SimpleTokenizer.INSTANCE;
            String[] tokens = tokenizer.tokenize(text);
            Span[] nameSpans = personFinder.find(tokens);

            if (nameSpans.length == 0) return text;

            // Rebuild text replacing detected names with tokens
            StringBuilder result = new StringBuilder(text);
            // Process spans in reverse order to preserve indices
            for (int i = nameSpans.length - 1; i >= 0; i--) {
                Span span = nameSpans[i];
                // Reconstruct the name from tokens
                StringBuilder name = new StringBuilder();
                for (int j = span.getStart(); j < span.getEnd(); j++) {
                    if (j > span.getStart()) name.append(" ");
                    name.append(tokens[j]);
                }

                String realName = name.toString();
                String token = vault.storeAndTokenize(sessionId, "NAME", realName);

                // Find and replace in original text
                int idx = result.indexOf(realName);
                if (idx >= 0) {
                    result.replace(idx, idx + realName.length(), token);
                }
            }

            personFinder.clearAdaptiveData();
            return result.toString();

        } catch (Exception e) {
            log.warning("NER processing failed: " + e.getMessage());
            return text; // graceful fallback
        }
    }

    public boolean isLoaded() {
        return modelLoaded;
    }
}