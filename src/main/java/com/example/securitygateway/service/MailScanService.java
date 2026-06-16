package com.example.securitygateway.service;

import com.example.securitygateway.model.LinkReport;
import com.example.securitygateway.model.LlmThreatAssessment;
import com.example.securitygateway.model.ScanRequest;
import com.example.securitygateway.model.ScanResult;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Orchestrates a full scan: it asks the LLM for a content assessment, runs deterministic link
 * sanitization, then fuses both into a single risk score and an ALLOW / QUARANTINE / BLOCK verdict.
 *
 * <p>The link layer can only ever <em>raise</em> the risk — a dangerous URL escalates an email the
 * model might have under-rated, but clean links never lower the model's score.
 */
@Service
public class MailScanService {

    /** A confirmed dangerous link floors the combined score here, regardless of the LLM. */
    static final int DANGEROUS_LINK_FLOOR = 75;
    static final int BLOCK_THRESHOLD = 75;
    static final int QUARANTINE_THRESHOLD = 50;

    private final PhishingDetectionService phishingDetectionService;
    private final LinkSanitizerService linkSanitizerService;

    public MailScanService(PhishingDetectionService phishingDetectionService,
                           LinkSanitizerService linkSanitizerService) {
        this.phishingDetectionService = phishingDetectionService;
        this.linkSanitizerService = linkSanitizerService;
    }

    public ScanResult scan(ScanRequest request) {
        LlmThreatAssessment assessment = phishingDetectionService.assess(request);
        List<LinkReport> links = linkSanitizerService.sanitize(request.body());

        boolean hasDangerousLink = links.stream().anyMatch(LinkReport::dangerous);
        int score = assessment.safeRiskScore();
        if (hasDangerousLink) {
            score = Math.max(score, DANGEROUS_LINK_FLOOR);
        }

        String verdict = verdictFor(score);
        String riskLevel = riskLevelFor(score);

        return new ScanResult(
                score,
                riskLevel,
                verdict,
                nullSafe(assessment.phishingIndicators()),
                nullSafe(assessment.manipulationTactics()),
                links,
                assessment.summary() == null ? "" : assessment.summary());
    }

    static String verdictFor(int score) {
        if (score >= BLOCK_THRESHOLD) {
            return "BLOCK";
        }
        if (score >= QUARANTINE_THRESHOLD) {
            return "QUARANTINE";
        }
        return "ALLOW";
    }

    static String riskLevelFor(int score) {
        if (score >= BLOCK_THRESHOLD) {
            return "CRITICAL";
        }
        if (score >= QUARANTINE_THRESHOLD) {
            return "HIGH";
        }
        if (score >= 25) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private static <T> List<T> nullSafe(List<T> list) {
        return list == null ? List.of() : list;
    }
}
