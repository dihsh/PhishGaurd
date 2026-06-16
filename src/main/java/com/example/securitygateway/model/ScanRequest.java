package com.example.securitygateway.model;

/**
 * An inbound email handed to the gateway for inspection.
 *
 * @param sender  the envelope / From address (may be spoofed — treated as untrusted input)
 * @param subject the email subject line
 * @param body    the raw email body (plain text or HTML)
 */
public record ScanRequest(String sender, String subject, String body) {
}
