package com.piiguard.piiguard.privacy;

import jakarta.annotation.PostConstruct;
import opennlp.tools.namefind.NameFinderME;
import opennlp.tools.namefind.TokenNameFinderModel;
import opennlp.tools.tokenize.SimpleTokenizer;
import opennlp.tools.util.Span;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Statistical detection of person names, which no regex can express.
 *
 * <p>"Rose" is a flower, a colour, a verb and a person, and only the surrounding words decide
 * which. A maximum-entropy sequence model scores each token against its context, which is why
 * this layer exists alongside the pattern matcher rather than instead of it.
 *
 * <h3>Two serious defects fixed here</h3>
 *
 * <p><b>The model instance was shared across concurrent requests.</b> {@link NameFinderME} is
 * documented as not thread-safe — it carries mutable adaptive state that accumulates evidence
 * across a document. As a Spring singleton called from many Tomcat worker threads at once,
 * that state was being read and cleared concurrently. The consequences run from wrong results
 * to the specific nightmare this product exists to prevent: one user's names influencing the
 * detection performed on another user's prompt. The model object itself is immutable and safe
 * to share, so the fix is a {@link ThreadLocal} finder per thread over one shared model —
 * correct, and it costs no extra memory for the model weights.
 *
 * <p><b>Redaction used {@code indexOf} instead of the match position.</b> OpenNLP returns spans
 * in <em>token</em> coordinates; the old code rebuilt the name by joining tokens with spaces
 * and searched for that string in the raw text. When the tokeniser split punctuation —
 * {@code O'Brien} becomes {@code O ' Brien}, {@code Smith,} becomes {@code Smith ,} — the
 * reconstructed string did not exist in the source, {@code indexOf} returned {@code -1}, and
 * the name was silently left in the prompt <em>after</em> a token had been issued for it.
 * A redaction failure that reports success. Using {@code tokenizePos} to recover true character
 * offsets removes the guesswork entirely.
 */
@Component
public class NerService {

    private static final Logger log = LoggerFactory.getLogger(NerService.class);

    /** Names are contextual guesses, so they lose to any structured detector on a tie. */
    private static final int PRIORITY = 40;

    private volatile TokenNameFinderModel model;
    private ThreadLocal<NameFinderME> finder;

    @PostConstruct
    public void loadModel() {
        try (InputStream modelStream =
                     getClass().getClassLoader().getResourceAsStream("en-ner-person.bin")) {

            if (modelStream == null) {
                log.warn("en-ner-person.bin not found on the classpath — name detection is DISABLED. "
                       + "Structured PII detection is unaffected.");
                return;
            }

            model = new TokenNameFinderModel(modelStream);
            finder = ThreadLocal.withInitial(() -> new NameFinderME(model));
            log.info("NER person model loaded");

        } catch (Exception e) {
            log.warn("NER model failed to load — name detection is DISABLED: {}", e.getMessage());
        }
    }

    /**
     * Returns name spans in character offsets of {@code text}. Never throws: a model failure
     * degrades name coverage, and the caller decides whether that is acceptable, but it must
     * not take down a request whose structured PII was redacted correctly.
     */
    public List<PiiFinding> detect(String text) {
        if (!isLoaded()) {
            return List.of();
        }

        try {
            // Character offsets of each token in the ORIGINAL string — the whole point.
            Span[] tokenPositions = SimpleTokenizer.INSTANCE.tokenizePos(text);
            if (tokenPositions.length == 0) {
                return List.of();
            }

            String[] tokens = new String[tokenPositions.length];
            for (int i = 0; i < tokenPositions.length; i++) {
                tokens[i] = text.substring(tokenPositions[i].getStart(), tokenPositions[i].getEnd());
            }

            NameFinderME nameFinder = finder.get();
            Span[] nameSpans = nameFinder.find(tokens);

            // Adaptive state is per-document. Not clearing it lets the previous request's
            // names bias this one — the same cross-request contamination the ThreadLocal
            // prevents, arriving by a different route.
            nameFinder.clearAdaptiveData();

            List<PiiFinding> findings = new ArrayList<>(nameSpans.length);
            for (Span span : nameSpans) {
                int start = tokenPositions[span.getStart()].getStart();
                int end = tokenPositions[span.getEnd() - 1].getEnd();
                findings.add(new PiiFinding(
                        start, end, PiiEntityType.NAME, text.substring(start, end), "NER", PRIORITY));
            }
            return findings;

        } catch (Exception e) {
            log.warn("NER detection failed, continuing without name coverage: {}", e.getMessage());
            return List.of();
        }
    }

    public boolean isLoaded() {
        return model != null && finder != null;
    }
}
