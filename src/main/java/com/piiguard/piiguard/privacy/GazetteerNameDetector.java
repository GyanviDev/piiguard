package com.piiguard.piiguard.privacy;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lexicon-based name detection, covering the gap the statistical model leaves.
 *
 * <h3>Why this exists</h3>
 *
 * <p>{@link NerService} uses OpenNLP's English person model, trained predominantly on Western
 * newswire. Measured against this system it redacts "John Smith" and "Michael Johnson"
 * reliably and misses "Priya Sharma" and "Rahul Verma" entirely — not intermittently,
 * completely. That is a training-distribution bias, and in a product intended for Indian
 * deployment it is the most consequential correctness defect available: the redactor works on
 * the names it was demonstrated with and silently forwards the names of the actual users.
 *
 * <p>The two techniques fail in opposite directions, which is exactly why running both is
 * worth the cost. A model generalises to names nobody enumerated but inherits its corpus's
 * demographics. A lexicon has no generalisation at all but perfect, auditable recall on what
 * it contains. Neither alone is adequate; together the coverage gap narrows substantially and
 * — more usefully — the remaining gap is one you can describe precisely.
 *
 * <h3>Controlling false positives</h3>
 *
 * <p>A name list is a blunt instrument, and over-redaction is not a harmless error: it corrupts
 * legitimate prompts, degrades answers, and is how a privacy control earns a reputation as
 * something to switch off. Three constraints keep it narrow:
 *
 * <ul>
 *   <li><b>Capitalisation is required.</b> The lexicon holds capitalised forms and matching is
 *       case-sensitive, so "we should <i>anand</i>..." in lower-case prose is not a person.</li>
 *   <li><b>Adjacent matches merge.</b> "Priya Sharma" becomes one {@code NAME} span rather than
 *       two, which preserves the fact that it refers to one person.</li>
 *   <li><b>Lowest priority of any detector.</b> If a pattern rule or the model claims the same
 *       text, they win — the lexicon only fills gaps.</li>
 * </ul>
 */
@Component
public class GazetteerNameDetector {

    private static final Logger log = LoggerFactory.getLogger(GazetteerNameDetector.class);

    private static final String RESOURCE = "name-gazetteer.txt";

    /**
     * Candidate tokens: a capitalised word, optionally with an internal apostrophe or hyphen.
     * Flat and bounded — no nested quantifiers, so no backtracking risk on hostile input.
     */
    private static final Pattern CANDIDATE = Pattern.compile("\\b\\p{Lu}[\\p{L}]{1,30}(?:['-]\\p{L}{1,30})?\\b");

    /** Sits below {@link NerService}'s priority, so the model's judgement wins any overlap. */
    private static final int PRIORITY = 35;

    private Set<String> lexicon = Set.of();

    @PostConstruct
    public void load() {
        Set<String> entries = new HashSet<>();

        try (InputStream stream = getClass().getClassLoader().getResourceAsStream(RESOURCE)) {
            if (stream == null) {
                log.warn("{} not found — lexicon name detection is disabled", RESOURCE);
                return;
            }
            try (BufferedReader reader =
                         new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String entry = line.trim();
                    if (!entry.isEmpty() && !entry.startsWith("#")) {
                        entries.add(entry);
                    }
                }
            }
            lexicon = Set.copyOf(entries);
            log.info("Name lexicon loaded: {} entries", lexicon.size());

        } catch (Exception e) {
            log.warn("Failed to load {} — lexicon name detection is disabled: {}",
                    RESOURCE, e.getMessage());
        }
    }

    /**
     * Returns merged spans for consecutive lexicon hits. Runs over the same unmodified text as
     * every other detector and rewrites nothing; the pipeline resolves overlaps centrally.
     */
    public List<PiiFinding> detect(String text) {
        if (lexicon.isEmpty()) {
            return List.of();
        }

        List<PiiFinding> findings = new ArrayList<>();
        Matcher matcher = CANDIDATE.matcher(text);

        int runStart = -1;
        int runEnd = -1;
        int previousEnd = -1;

        while (matcher.find()) {
            boolean isName = lexicon.contains(matcher.group());

            // A run continues only across pure whitespace. "Priya Sharma" merges; "Priya, Sharma"
            // and "Priya and Sharma" do not, because those are two people.
            boolean contiguous = runStart >= 0
                    && matcher.start() > previousEnd
                    && text.substring(previousEnd, matcher.start()).isBlank();

            if (isName && contiguous) {
                runEnd = matcher.end();
            } else {
                if (runStart >= 0) {
                    findings.add(finding(text, runStart, runEnd));
                    runStart = -1;
                }
                if (isName) {
                    runStart = matcher.start();
                    runEnd = matcher.end();
                }
            }
            previousEnd = matcher.end();
        }

        if (runStart >= 0) {
            findings.add(finding(text, runStart, runEnd));
        }
        return findings;
    }

    private PiiFinding finding(String text, int start, int end) {
        return new PiiFinding(
                start, end, PiiEntityType.NAME, text.substring(start, end), "GAZETTEER", PRIORITY);
    }

    public int size() {
        return lexicon.size();
    }
}
