package com.example.securitygateway.service;

import com.example.securitygateway.model.LlmThreatAssessment;
import com.example.securitygateway.model.ScanRequest;
import com.example.securitygateway.model.ScanResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Verdict-fusion tests. The LLM call is mocked, so these run offline; the real
 * {@link LinkSanitizerService} is used to prove link escalation end-to-end.
 */
@ExtendWith(MockitoExtension.class)
class MailScanServiceTest {

    @Mock
    private PhishingDetectionService phishingDetectionService;

    private MailScanService service;

    @BeforeEach
    void setUp() {
        service = new MailScanService(phishingDetectionService, new LinkSanitizerService());
    }

    private void stubLlm(int score) {
        when(phishingDetectionService.assess(org.mockito.ArgumentMatchers.any()))
                .thenReturn(new LlmThreatAssessment(score, List.of(), List.of(), "stub"));
    }

    @Test
    @DisplayName("low score + clean body -> ALLOW / LOW")
    void allow() {
        stubLlm(10);
        ScanResult result = service.scan(new ScanRequest("a@b.com", "hi", "totally normal email"));
        assertThat(result.verdict()).isEqualTo("ALLOW");
        assertThat(result.riskLevel()).isEqualTo("LOW");
        assertThat(result.riskScore()).isEqualTo(10);
    }

    @Test
    @DisplayName("mid score -> QUARANTINE / HIGH")
    void quarantine() {
        stubLlm(60);
        ScanResult result = service.scan(new ScanRequest("a@b.com", "hi", "win a prize now"));
        assertThat(result.verdict()).isEqualTo("QUARANTINE");
        assertThat(result.riskLevel()).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("high score -> BLOCK / CRITICAL")
    void block() {
        stubLlm(90);
        ScanResult result = service.scan(new ScanRequest("a@b.com", "hi", "send your password"));
        assertThat(result.verdict()).isEqualTo("BLOCK");
        assertThat(result.riskLevel()).isEqualTo("CRITICAL");
    }

    @Test
    @DisplayName("a dangerous link escalates an LLM-underrated email to BLOCK")
    void dangerousLinkEscalates() {
        stubLlm(5); // model thought it was harmless...
        ScanResult result = service.scan(new ScanRequest(
                "a@b.com", "hi", "verify here http://192.168.0.9/login now"));
        assertThat(result.riskScore()).isGreaterThanOrEqualTo(MailScanService.DANGEROUS_LINK_FLOOR);
        assertThat(result.verdict()).isEqualTo("BLOCK");
        assertThat(result.links()).anyMatch(l -> l.dangerous());
    }

    @Test
    @DisplayName("null indicator lists from the model are normalized to empty lists")
    void nullListsNormalized() {
        when(phishingDetectionService.assess(org.mockito.ArgumentMatchers.any()))
                .thenReturn(new LlmThreatAssessment(20, null, null, null));
        ScanResult result = service.scan(new ScanRequest("a@b.com", "s", "body"));
        assertThat(result.phishingIndicators()).isEmpty();
        assertThat(result.manipulationTactics()).isEmpty();
        assertThat(result.summary()).isEmpty();
    }
}
