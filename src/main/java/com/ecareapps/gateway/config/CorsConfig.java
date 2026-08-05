package com.ecareapps.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsWebFilter;

import java.util.List;

/**
 * VAPT Section B.1 — strict CORS allow-list (fixes finding #6 "overly permissive CORS").
 *
 * <p>Only the known product/theme origins are permitted. Spring reflects the single matching
 * Origin back (never {@code *}), and credentials are allowed only because the list is explicit.
 * No {@code "+"}, no broad wildcards — the one wildcard is a bounded subdomain pattern
 * ({@code http://*.ecarehealth.com}) matching the webOrigins registered in Keycloak.
 */
@Configuration
public class CorsConfig {

    // Exact origins (Keycloak webOrigins). One bounded subdomain PATTERN for tenant subdomains.
    private static final List<String> ALLOWED_ORIGIN_PATTERNS = List.of(
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:8080",
        "http://auth.ecareapps.com",
        "https://auth.ecareapps.com",
        "http://ecarehealth.com",
        "https://ecarehealth.com",
        "http://*.ecarehealth.com",
        "https://*.ecarehealth.com"
    );

    @Bean
    public CorsWebFilter corsWebFilter(CorsConfigurationSource source) {
        return new CorsWebFilter(source);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        // allowedOriginPatterns (not allowedOrigins) so the bounded "*.ecarehealth.com"
        // subdomain pattern works while still reflecting only the matching origin.
        cfg.setAllowedOriginPatterns(ALLOWED_ORIGIN_PATTERNS);
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept",
            "Origin", "X-Requested-With"));
        cfg.setExposedHeaders(List.of("Authorization"));
        cfg.setAllowCredentials(true);
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }
}
