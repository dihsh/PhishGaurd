package com.example.securitygateway.service;

import com.example.securitygateway.model.LinkReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit tests for the deterministic link heuristics — no Spring context, no LLM, no network.
 */
class LinkSanitizerServiceTest {

    private final LinkSanitizerService service = new LinkSanitizerService();

    @Test
    @DisplayName("blank or link-free body yields no reports")
    void noLinks() {
        assertThat(service.sanitize(null)).isEmpty();
        assertThat(service.sanitize("   ")).isEmpty();
        assertThat(service.sanitize("just some text with no urls")).isEmpty();
    }

    @Test
    @DisplayName("a normal HTTPS brand URL is not flagged")
    void cleanLink() {
        List<LinkReport> reports = service.sanitize("See https://www.paypal.com/account for details.");
        assertThat(reports).hasSize(1);
        assertThat(reports.get(0).dangerous()).isFalse();
    }

    @Test
    @DisplayName("raw IP host is flagged")
    void ipHost() {
        LinkReport r = service.sanitize("login at http://192.168.10.5/login").get(0);
        assertThat(r.dangerous()).isTrue();
        assertThat(r.reason()).contains("raw IP address");
    }

    @Test
    @DisplayName("URL shortener is flagged")
    void shortener() {
        LinkReport r = service.sanitize("click https://bit.ly/3xZ").get(0);
        assertThat(r.dangerous()).isTrue();
        assertThat(r.reason()).contains("shortener");
    }

    @Test
    @DisplayName("high-risk TLD is flagged")
    void riskyTld() {
        LinkReport r = service.sanitize("download https://invoice.zip/now").get(0);
        assertThat(r.dangerous()).isTrue();
        assertThat(r.reason()).contains("high-risk top-level domain");
    }

    @Test
    @DisplayName("brand look-alike domain is flagged")
    void brandImpersonation() {
        LinkReport r = service.sanitize("verify at https://paypal.secure-login.com/").get(0);
        assertThat(r.dangerous()).isTrue();
        assertThat(r.reason()).contains("impersonating");
    }

    @Test
    @DisplayName("userinfo '@' trick is flagged")
    void userinfoTrick() {
        LinkReport r = service.sanitize("go to http://apple.com@evil.example.org/").get(0);
        assertThat(r.dangerous()).isTrue();
        assertThat(r.reason()).contains("userinfo");
    }

    @Test
    @DisplayName("credential keyword in the path is flagged")
    void credentialPath() {
        LinkReport r = service.sanitize("http://random-host.example.net/secure/verify-account").get(0);
        assertThat(r.dangerous()).isTrue();
        assertThat(r.reason()).contains("credential-harvesting keyword");
    }

    @Test
    @DisplayName("defang renders the URL un-clickable")
    void defang() {
        assertThat(service.defang("https://bad.site/login"))
                .isEqualTo("hxxps://bad[.]site/login");
    }

    @Test
    @DisplayName("multiple links are each inspected and trailing punctuation stripped")
    void multipleLinks() {
        List<LinkReport> reports = service.sanitize(
                "first https://www.google.com, then http://192.168.0.1/login.");
        assertThat(reports).hasSize(2);
        assertThat(reports.get(0).dangerous()).isFalse();
        assertThat(reports.get(0).original()).isEqualTo("https://www.google.com");
        assertThat(reports.get(1).dangerous()).isTrue();
    }
}
