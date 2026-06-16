package com.example.securitygateway.service;

import com.example.securitygateway.model.LinkReport;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic URL extraction and sanitization.
 *
 * <p>This layer is intentionally LLM-free: link tricks (IP hosts, look-alike domains, userinfo
 * spoofing, risky TLDs, shorteners) are detected with stable heuristics so the verdict is
 * reproducible and cannot be talked out of by a cleverly worded email. Every URL is also
 * "defanged" into an un-clickable form so it can be safely shown in a quarantine UI.
 */
@Service
public class LinkSanitizerService {

    /** Matches http/https URLs in free text. */
    private static final Pattern URL_PATTERN =
            Pattern.compile("https?://[^\\s\"'<>)\\]]+", Pattern.CASE_INSENSITIVE);

    /** Bare IPv4 literal used as a host — legitimate brands almost never do this. */
    private static final Pattern IPV4_HOST = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    /** Known URL-shortener hosts that hide the real destination. */
    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
            "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at");

    /** TLDs disproportionately abused for phishing / malware delivery. */
    private static final Set<String> RISKY_TLDS = Set.of(
            "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml",
            "cf", "ga", "work", "fit", "review", "kim", "loan");

    /** Words that, in a path, suggest credential harvesting. */
    private static final Set<String> CREDENTIAL_WORDS = Set.of(
            "login", "log-in", "signin", "sign-in", "verify", "secure", "account",
            "update", "confirm", "password", "webscr", "banking", "wallet");

    /** Brand names commonly impersonated; flagged when they appear as a sub-label, not the real domain. */
    private static final Set<String> IMPERSONATED_BRANDS = Set.of(
            "paypal", "apple", "microsoft", "google", "amazon", "netflix",
            "facebook", "instagram", "bank", "dhl", "fedex", "ups", "irs");

    /**
     * Extract every URL in {@code body} and produce one {@link LinkReport} per URL.
     * Returns an empty list when the body is null/blank or contains no links.
     */
    public List<LinkReport> sanitize(String body) {
        List<LinkReport> reports = new ArrayList<>();
        if (body == null || body.isBlank()) {
            return reports;
        }
        Matcher matcher = URL_PATTERN.matcher(body);
        while (matcher.find()) {
            String url = stripTrailingPunctuation(matcher.group());
            reports.add(inspect(url));
        }
        return reports;
    }

    private LinkReport inspect(String url) {
        List<String> reasons = new ArrayList<>();
        String lower = url.toLowerCase(Locale.ROOT);

        String host = extractHost(lower);
        String path = extractPath(lower);

        if (lower.startsWith("http://")) {
            reasons.add("unencrypted HTTP link");
        }
        if (host.contains("@")) {
            reasons.add("userinfo '@' in URL hides the true destination host");
        }
        String bareHost = host.contains("@") ? host.substring(host.indexOf('@') + 1) : host;
        if (IPV4_HOST.matcher(bareHost).matches()) {
            reasons.add("raw IP address used as host instead of a domain name");
        }
        if (bareHost.startsWith("xn--") || bareHost.contains(".xn--")) {
            reasons.add("punycode/internationalized domain — possible homograph spoofing");
        }
        if (SHORTENERS.contains(bareHost)) {
            reasons.add("URL shortener conceals the real destination");
        }
        String tld = topLevelDomain(bareHost);
        if (RISKY_TLDS.contains(tld)) {
            reasons.add("high-risk top-level domain '." + tld + "'");
        }
        if (impersonatesBrand(bareHost)) {
            reasons.add("look-alike domain impersonating a well-known brand");
        }
        // Credential keywords are common on legitimate HTTPS sites (e.g. paypal.com/account), so they
        // only count as a signal when the link is also unencrypted — a real login is never plain HTTP.
        if (lower.startsWith("http://")) {
            for (String word : CREDENTIAL_WORDS) {
                if (path.contains(word)) {
                    reasons.add("credential-harvesting keyword '" + word + "' on an unencrypted link");
                    break;
                }
            }
        }

        boolean dangerous = !reasons.isEmpty();
        String reason = dangerous ? String.join("; ", reasons) : "no suspicious link heuristics matched";
        return new LinkReport(url, defang(url), dangerous, reason);
    }

    /** Turn a URL into an un-clickable, render-safe form. */
    public String defang(String url) {
        return url.replace("http", "hxxp").replace(".", "[.]");
    }

    private static String extractHost(String lowerUrl) {
        String afterScheme = lowerUrl.replaceFirst("^https?://", "");
        int slash = afterScheme.indexOf('/');
        String authority = slash >= 0 ? afterScheme.substring(0, slash) : afterScheme;
        int colon = authority.indexOf(':');
        // keep a possible '@' so the caller can detect userinfo spoofing
        return colon >= 0 && authority.indexOf('@') < 0 ? authority.substring(0, colon) : authority;
    }

    private static String extractPath(String lowerUrl) {
        String afterScheme = lowerUrl.replaceFirst("^https?://", "");
        int slash = afterScheme.indexOf('/');
        return slash >= 0 ? afterScheme.substring(slash) : "";
    }

    private static String topLevelDomain(String host) {
        int dot = host.lastIndexOf('.');
        return dot >= 0 && dot < host.length() - 1 ? host.substring(dot + 1) : "";
    }

    /**
     * A brand is "impersonated" when its name appears in the host but is not the registrable
     * domain label, e.g. {@code paypal.secure-login.com} or {@code apple-id-verify.xyz}.
     */
    private static boolean impersonatesBrand(String host) {
        for (String brand : IMPERSONATED_BRANDS) {
            if (!host.contains(brand)) {
                continue;
            }
            String registrable = registrableLabel(host);
            if (!registrable.equals(brand)) {
                return true;
            }
        }
        return false;
    }

    /** The label immediately left of the TLD, e.g. {@code mail.paypal.com -> paypal}. */
    private static String registrableLabel(String host) {
        String[] parts = host.split("\\.");
        return parts.length >= 2 ? parts[parts.length - 2] : host;
    }

    private static String stripTrailingPunctuation(String url) {
        return url.replaceAll("[.,;:!?)\\]]+$", "");
    }
}
