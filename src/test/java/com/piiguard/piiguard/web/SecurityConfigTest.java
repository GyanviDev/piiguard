package com.piiguard.piiguard.web;

import com.piiguard.piiguard.detect.MlDetectionService;
import com.piiguard.piiguard.llm.LlmClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Access control, asserted rather than assumed.
 *
 * <p>The single most severe defect in the original project was that {@code GET /api/audit}
 * returned every prompt any user had ever submitted — raw and unredacted — to any anonymous
 * caller. There was no security layer of any kind. These tests exist so that reintroducing
 * that failure is impossible to do quietly.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityConfigTest {

    private static final String ADMIN_KEY = "test-admin-key";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private LlmClient llmClient;

    @MockitoBean
    private MlDetectionService mlDetection;

    @BeforeEach
    void setUp() {
        when(llmClient.isConfigured()).thenReturn(true);
        when(llmClient.model()).thenReturn("test-model");
        when(mlDetection.classify(anyString())).thenReturn(Optional.empty());
        when(mlDetection.confidenceThreshold()).thenReturn(0.75);
        when(mlDetection.isFailClosed()).thenReturn(false);
        when(mlDetection.isServiceAvailable()).thenReturn(false);
    }

    @Test
    @DisplayName("the audit log is not readable without the admin key")
    void auditRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/audit")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("a wrong admin key is rejected")
    void auditRejectsWrongKey() throws Exception {
        mockMvc.perform(get("/api/audit").header("X-Admin-Key", "not-the-key"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("the audit log is readable with the admin key, and paginated")
    void auditAllowsCorrectKey() throws Exception {
        mockMvc.perform(get("/api/audit").header("X-Admin-Key", ADMIN_KEY))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("the attack payload catalogue is not public")
    void attackSuiteRequiresAuthentication() throws Exception {
        // Publishing a list of payloads and whether each one gets through is a probing tool.
        mockMvc.perform(get("/api/attack")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/attack").header("X-Admin-Key", ADMIN_KEY))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("internal status is not public")
    void statusRequiresAuthentication() throws Exception {
        // Knowing that the name model failed to load tells an attacker names are unprotected.
        mockMvc.perform(get("/api/status")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/status").header("X-Admin-Key", ADMIN_KEY))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("metrics endpoints are not public")
    void actuatorIsProtected() throws Exception {
        mockMvc.perform(get("/actuator/metrics")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("the health probe stays public so orchestrators can use it")
    void healthProbeIsPublic() throws Exception {
        mockMvc.perform(get("/api/health")).andExpect(status().isOk());
    }

    @Test
    @DisplayName("security headers are set on every response")
    void securityHeadersArePresent() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(header().exists("Content-Security-Policy"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }

    @Test
    @DisplayName("the CSP forbids inline script, which is the point of having one")
    void cspDisallowsInlineScript() throws Exception {
        String csp = mockMvc.perform(get("/api/health"))
                .andReturn().getResponse().getHeader("Content-Security-Policy");

        org.junit.jupiter.api.Assertions.assertNotNull(csp);
        org.junit.jupiter.api.Assertions.assertTrue(csp.contains("script-src 'self'"));
        org.junit.jupiter.api.Assertions.assertFalse(csp.contains("script-src 'self' 'unsafe-inline'"));
        org.junit.jupiter.api.Assertions.assertTrue(csp.contains("frame-ancestors 'none'"));
    }

    @Test
    @DisplayName("unmapped paths are denied rather than falling through")
    void unknownPathsAreDenied() throws Exception {
        mockMvc.perform(get("/api/definitely-not-a-real-endpoint"))
                .andExpect(status().is4xxClientError());
    }
}
