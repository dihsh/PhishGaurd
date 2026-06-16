package com.example.securitygateway.controller;

import com.example.securitygateway.model.ScanResult;
import com.example.securitygateway.service.MailScanService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-layer tests. Only the controller is loaded and {@link MailScanService} is mocked, so the
 * Ollama auto-configuration never starts — these pass with no model running.
 */
@WebMvcTest(MailScanController.class)
class MailScanControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private MailScanService mailScanService;

    @Test
    void scanReturnsAssessment() throws Exception {
        when(mailScanService.scan(any())).thenReturn(new ScanResult(
                88, "CRITICAL", "BLOCK",
                List.of("credential-harvesting link"),
                List.of("false urgency"),
                List.of(), "Phishing attempt impersonating a bank."));

        String json = """
                {"sender":"security@bank-alert.xyz","subject":"Account locked","body":"Verify now or lose access."}
                """;

        mockMvc.perform(post("/api/scan").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict").value("BLOCK"))
                .andExpect(jsonPath("$.riskLevel").value("CRITICAL"))
                .andExpect(jsonPath("$.riskScore").value(88))
                .andExpect(jsonPath("$.phishingIndicators[0]").value("credential-harvesting link"));
    }

    @Test
    void blankBodyIsRejected() throws Exception {
        String json = "{\"sender\":\"a@b.com\",\"subject\":\"hi\",\"body\":\"   \"}";
        mockMvc.perform(post("/api/scan").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }
}
