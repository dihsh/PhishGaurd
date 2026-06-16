package com.example.securitygateway.model;

/**
 * Result of inspecting a single URL found in the email body.
 *
 * @param original  the URL exactly as it appeared in the email
 * @param defanged  a neutralized, un-clickable form (e.g. {@code hxxps://bad[.]site}) safe to render
 * @param dangerous whether the link tripped one or more heuristics
 * @param reason    human-readable explanation of why it was flagged (or why it looks clean)
 */
public record LinkReport(String original, String defanged, boolean dangerous, String reason) {
}
