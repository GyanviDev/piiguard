package com.piiguard.piiguard.privacy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GazetteerNameDetectorTest {

    private GazetteerNameDetector detector;

    @BeforeEach
    void setUp() {
        detector = new GazetteerNameDetector();
        detector.load();
    }

    @Test
    @DisplayName("the lexicon loads")
    void lexiconLoads() {
        assertTrue(detector.size() > 150, "Expected a populated lexicon, got " + detector.size());
    }

    @Test
    @DisplayName("names the statistical model misses are detected")
    void detectsNamesTheModelMisses() {
        // Verified against the running system: the OpenNLP English person model returns nothing
        // for either of these, while detecting "John Smith" reliably. That asymmetry is the
        // entire reason this detector exists.
        List<PiiFinding> findings = detector.detect("Priya Sharma will meet Rahul Verma tomorrow.");

        assertEquals(2, findings.size());
        assertEquals("Priya Sharma", findings.get(0).value());
        assertEquals("Rahul Verma", findings.get(1).value());
    }

    @Test
    @DisplayName("a given name and surname merge into one span")
    void mergesAdjacentTokens() {
        List<PiiFinding> findings = detector.detect("Contact Ananya Iyer about it.");

        assertEquals(1, findings.size(), "One person must be one span, not two");
        assertEquals("Ananya Iyer", findings.get(0).value());
        assertEquals(PiiEntityType.NAME, findings.get(0).type());
    }

    @Test
    @DisplayName("names separated by punctuation stay separate people")
    void doesNotMergeAcrossPunctuation() {
        List<PiiFinding> findings = detector.detect("Invite Priya, Rahul and Deepika.");

        assertEquals(3, findings.size());
        findings.forEach(f -> assertEquals(1, f.value().split("\\s+").length));
    }

    @Test
    @DisplayName("spans point at the right characters")
    void spansAreAccurate() {
        String text = "Please email Priya Sharma today.";
        PiiFinding finding = detector.detect(text).get(0);

        assertEquals("Priya Sharma", text.substring(finding.start(), finding.end()));
    }

    @Test
    @DisplayName("lower-case prose is not treated as a name")
    void requiresCapitalisation() {
        // Several lexicon entries are also words or name fragments in other contexts. Requiring
        // a capital is the cheapest constraint that keeps ordinary prose intact.
        assertTrue(detector.detect("the anand of the situation was verma at best").isEmpty());
    }

    @Test
    @DisplayName("ordinary business prose produces no findings")
    void noFalsePositivesOnBusinessProse() {
        assertTrue(detector.detect("Summarize the Q3 Revenue Report and flag Key Risks.").isEmpty());
        assertTrue(detector.detect("Review the Kubernetes Deployment and the Docker Image.").isEmpty());
    }

    @Test
    @DisplayName("it defers to stronger detectors on priority")
    void hasLowestPriority() {
        // A lexicon hit is weaker evidence than either a validated pattern or the model, so it
        // must lose any contested span rather than win it.
        PiiFinding finding = detector.detect("Ask Priya.").get(0);
        assertTrue(finding.priority() < 40, "Lexicon must sit below the NER model's priority");
    }

    @Test
    @DisplayName("hostile input terminates quickly")
    void isNotVulnerableToRedos() {
        String input = "Priya".repeat(2_000).substring(0, 10_000);

        long start = System.nanoTime();
        detector.detect(input);
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        assertTrue(elapsedMillis < 1_000, "Took " + elapsedMillis + "ms");
    }
}
