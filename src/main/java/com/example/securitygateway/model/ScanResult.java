package com.example.securitygateway.model;

import java.util.List;

/**
 * The final, combined verdict returned to the caller (the MTA filter / quarantine system).
 *
 * <p>Merges the LLM's content assessment with deterministic link analysis into a single
 * actionable score and verdict.
 *
 * @param riskScore           combined 0-100 risk (LLM score escalated by dangerous links)
 * @param riskLevel           LOW / MEDIUM / HIGH / CRITICAL bucket derived from {@code riskScore}
 * @param verdict             ALLOW / QUARANTINE / BLOCK action recommendation
 * @param phishingIndicators  phishing signals reported by the LLM
 * @param manipulationTactics social-engineering tactics reported by the LLM
 * @param links               per-URL sanitization reports
 * @param summary             one-line human-readable explanation
 */
public record ScanResult(
        int riskScore,
        String riskLevel,
        String verdict,
        List<String> phishingIndicators,
        List<String> manipulationTactics,
        List<LinkReport> links,
        String summary) {
}
