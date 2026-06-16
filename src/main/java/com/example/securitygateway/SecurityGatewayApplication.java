package com.example.securitygateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * AI Phishing & Anti-Spam Security Gateway.
 *
 * <p>Sits between the mail transfer agent (MTA) and the inbox. Every inbound message is
 * scored for phishing risk by a local LLM (via Spring AI + Ollama) and its links are
 * sanitized, producing a structured threat assessment and an ALLOW / QUARANTINE / BLOCK verdict.
 */
@SpringBootApplication
public class SecurityGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityGatewayApplication.class, args);
    }
}
