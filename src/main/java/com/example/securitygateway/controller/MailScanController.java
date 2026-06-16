package com.example.securitygateway.controller;

import com.example.securitygateway.model.ScanRequest;
import com.example.securitygateway.model.ScanResult;
import com.example.securitygateway.service.MailScanService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * HTTP entry point for the gateway. A mail filter POSTs each inbound message here and acts on the
 * returned verdict.
 */
@RestController
@RequestMapping("/api")
public class MailScanController {

    private final MailScanService mailScanService;

    public MailScanController(MailScanService mailScanService) {
        this.mailScanService = mailScanService;
    }

    /** Scan a single email and return its structured threat assessment. */
    @PostMapping("/scan")
    public ResponseEntity<ScanResult> scan(@RequestBody ScanRequest request) {
        if (request == null || isBlank(request.body())) {
            throw new IllegalArgumentException("Field 'body' is required and must not be blank.");
        }
        return ResponseEntity.ok(mailScanService.scan(request));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadRequest(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleUpstreamFailure(Exception ex) {
        // Most commonly: Ollama is not running / model not pulled.
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("error", "Analysis engine unavailable: " + ex.getMessage()));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
