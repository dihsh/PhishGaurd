package com.example.securitygateway.model;

import com.fasterxml.jackson.annotation.JsonClassDescription;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;

import java.util.List;

/**
 * The structured threat assessment the LLM is forced to return.
 *
 * <p>Spring AI's structured-output converter turns this record into a JSON schema, embeds it in
 * the prompt, and validates/deserializes the model's reply back into this type. The
 * {@code @JsonPropertyDescription} hints become part of that schema, which is how we get a free,
 * local model to emit reliable, machine-readable safety scores (strict schema validation).
 */
@JsonClassDescription("Structured security assessment of a single email body.")
public record LlmThreatAssessment(

        @JsonPropertyDescription("Integer phishing/spam risk from 0 (clearly safe) to 100 (clearly malicious).")
        int riskScore,

        @JsonPropertyDescription("Concrete phishing indicators found, e.g. 'spoofed sender domain', "
                + "'credential-harvesting link', 'mismatched display name'. Empty if none.")
        List<String> phishingIndicators,

        @JsonPropertyDescription("Psychological manipulation or social-engineering tactics detected, e.g. "
                + "'false urgency', 'authority impersonation', 'fear of account loss'. Empty if none.")
        List<String> manipulationTactics,

        @JsonPropertyDescription("One concise sentence explaining the verdict for a security analyst.")
        String summary) {

    /** Null-safe accessor used by downstream scoring so a partial LLM reply never NPEs. */
    public int safeRiskScore() {
        return Math.max(0, Math.min(100, riskScore));
    }
}
