package com.piiguard.piiguard.web;

import com.piiguard.piiguard.audit.AuditLog;
import com.piiguard.piiguard.audit.AuditLogRepository;
import com.piiguard.piiguard.detect.AdversarialHarnessService;
import com.piiguard.piiguard.detect.MlDetectionService;
import com.piiguard.piiguard.llm.LlmClient;
import com.piiguard.piiguard.privacy.DifferentialPrivacyService;
import com.piiguard.piiguard.privacy.NerService;
import com.piiguard.piiguard.privacy.PrivacyBudgetAccountant;
import com.piiguard.piiguard.privacy.RegexSanitizer;
import com.piiguard.piiguard.privacy.TokenVault;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Operator endpoints. Every route here requires the admin key — see {@code SecurityConfig}.
 *
 * <p>Splitting these out of {@code ProxyController} is not cosmetic. Two audiences with two
 * different trust levels were being served by one class, which is exactly the arrangement that
 * makes "wait, is this endpoint public?" a question nobody can answer by looking. A separate
 * controller under a single security rule makes the answer structural.
 *
 * <p>Three of these were previously anonymous:
 * <ul>
 *   <li>{@code /api/audit} returned every prompt ever submitted, unpaginated, including the raw
 *       text — the most severe defect in the project.</li>
 *   <li>{@code /api/attack} publishes a working catalogue of payloads that get past or are
 *       caught by our detector. That is a probing tool handed to whoever asks.</li>
 *   <li>{@code /api/status} disclosed internal configuration and component state, which is
 *       reconnaissance: knowing the name model failed to load tells an attacker that names are
 *       currently unprotected.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class AdminController {

    private final AuditLogRepository auditRepository;
    private final AdversarialHarnessService harness;
    private final MlDetectionService mlDetection;
    private final NerService nerService;
    private final RegexSanitizer regexSanitizer;
    private final DifferentialPrivacyService dpService;
    private final PrivacyBudgetAccountant budgetAccountant;
    private final LlmClient llmClient;
    private final TokenVault vault;

    public AdminController(AuditLogRepository auditRepository,
                           AdversarialHarnessService harness,
                           MlDetectionService mlDetection,
                           NerService nerService,
                           RegexSanitizer regexSanitizer,
                           DifferentialPrivacyService dpService,
                           PrivacyBudgetAccountant budgetAccountant,
                           LlmClient llmClient,
                           TokenVault vault) {
        this.auditRepository = auditRepository;
        this.harness = harness;
        this.mlDetection = mlDetection;
        this.nerService = nerService;
        this.regexSanitizer = regexSanitizer;
        this.dpService = dpService;
        this.budgetAccountant = budgetAccountant;
        this.llmClient = llmClient;
        this.vault = vault;
    }

    /** Paginated and capped — the old {@code findAll()} would serialise the entire table. */
    @GetMapping("/audit")
    public ResponseEntity<Page<AuditLog>> audit(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(defaultValue = "false") boolean attacksOnly) {

        PageRequest pageRequest = PageRequest.of(Math.max(0, page), Math.min(Math.max(1, size), 200));

        return ResponseEntity.ok(attacksOnly
                ? auditRepository.findByAttackDetectedTrueOrderByCreatedAtDesc(pageRequest)
                : auditRepository.findAllByOrderByCreatedAtDesc(pageRequest));
    }

    /**
     * Runs the detection regression suite live. Now includes benign control prompts that must
     * <em>not</em> be blocked, so the result can actually fail — the previous version only ever
     * tested payloads its own rules were written against and reported a guaranteed pass.
     */
    @GetMapping("/attack")
    public ResponseEntity<Map<String, Object>> attack() {
        List<Map<String, Object>> results = harness.runSuite();
        long passed = results.stream().filter(r -> Boolean.TRUE.equals(r.get("passed"))).count();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("total", results.size());
        body.put("passed", passed);
        body.put("failed", results.size() - passed);
        body.put("results", results);
        return ResponseEntity.ok(body);
    }

    /**
     * Component state. Every number here is read from the component that owns it rather than
     * hard-coded: the old version reported {@code "attackPatternsLoaded": 7} and
     * {@code "dpEpsilon": 0.1} as literals, so the moment a rule was added or a property
     * changed the status endpoint began confidently reporting something false — which is worse
     * than having no status endpoint.
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("nerModelLoaded", nerService.isLoaded());
        body.put("mlServiceAvailable", mlDetection.isServiceAvailable());
        body.put("mlFailClosed", mlDetection.isFailClosed());
        body.put("llmConfigured", llmClient.isConfigured());
        body.put("llmModel", llmClient.model());
        body.put("piiRuleCount", regexSanitizer.ruleCount());
        body.put("threatRuleCount", harness.ruleCount());
        body.put("harnessSuiteSize", harness.suiteSize());
        body.put("dpEnabled", dpService.isEnabled());
        body.put("dpEpsilon", dpService.epsilon());
        body.put("dpBudgetPerCaller", budgetAccountant.totalBudget());
        body.put("activeVaultSessions", vault.activeSessions());
        body.put("auditRecords", auditRepository.count());
        body.put("attacksBlockedTotal", auditRepository.countByAttackDetectedTrue());
        return ResponseEntity.ok(body);
    }
}
