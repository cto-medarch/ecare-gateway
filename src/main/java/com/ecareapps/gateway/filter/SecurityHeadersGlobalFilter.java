package com.ecareapps.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * VAPT Section B, findings #4–#8 — one global response-header filter applied to EVERY response
 * (including 401/403/405 error responses, since it runs before the security/routing machinery
 * and mutates headers in a {@code beforeCommit} hook).
 *
 * <ul>
 *   <li>#5  X-XSS-Protection: 1; mode=block</li>
 *   <li>#6  Content-Security-Policy: strict default-src (login theme origin allowed)</li>
 *   <li>#7  Strict-Transport-Security: max-age + includeSubDomains (HSTS)</li>
 *   <li>#4  Cookie HttpOnly — enforced on any pass-through Set-Cookie</li>
 *   <li>#8  Cookie Secure   — enforced on any pass-through Set-Cookie</li>
 * </ul>
 *
 * Also sets X-Content-Type-Options and a conservative Referrer-Policy as defense-in-depth.
 */
@Component
public class SecurityHeadersGlobalFilter implements GlobalFilter, Ordered {

    // Strict CSP. auth.ecareapps.com is allowed for the Keycloakify login theme assets (ADR-4).
    private static final String CSP =
        "default-src 'self'; "
        + "frame-ancestors 'none'; "
        + "base-uri 'self'; "
        + "form-action 'self' https://auth.ecareapps.com; "
        + "object-src 'none'";

    private static final String HSTS = "max-age=31536000; includeSubDomains";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // beforeCommit runs after routing has populated downstream headers (incl. Set-Cookie)
        // but before the response is flushed — the only safe point to normalize both.
        exchange.getResponse().beforeCommit(() -> {
            HttpHeaders headers = exchange.getResponse().getHeaders();

            headers.set("X-XSS-Protection", "1; mode=block");           // #5
            headers.set("Content-Security-Policy", CSP);                // #6
            headers.set("Strict-Transport-Security", HSTS);            // #7
            headers.set("X-Content-Type-Options", "nosniff");          // defense-in-depth
            headers.set("Referrer-Policy", "strict-origin-when-cross-origin");

            enforceCookieFlags(headers);                                // #4 + #8
            return Mono.empty();
        });
        return chain.filter(exchange);
    }

    /** Ensure every pass-through Set-Cookie carries HttpOnly (#4) and Secure (#8). */
    private void enforceCookieFlags(HttpHeaders headers) {
        List<String> cookies = headers.get(HttpHeaders.SET_COOKIE);
        if (cookies == null || cookies.isEmpty()) {
            return;
        }
        List<String> hardened = new ArrayList<>(cookies.size());
        for (String cookie : cookies) {
            hardened.add(harden(cookie));
        }
        headers.put(HttpHeaders.SET_COOKIE, hardened);
    }

    private String harden(String cookie) {
        String lower = cookie.toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder(cookie);
        if (!lower.contains("httponly")) {
            sb.append("; HttpOnly");
        }
        if (!lower.contains("secure")) {
            sb.append("; Secure");
        }
        return sb.toString();
    }

    @Override
    public int getOrder() {
        // Run first so the beforeCommit hook is registered before anything writes the response.
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
