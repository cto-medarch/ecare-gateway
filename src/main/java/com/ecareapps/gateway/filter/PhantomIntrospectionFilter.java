package com.ecareapps.gateway.filter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * THE PHANTOM SEAM — DO NOT VIOLATE (ADR-3).
 *
 * <p>Today the gateway runs pure JWT: it validates the token locally and forwards it UNCHANGED to
 * the product. Products receive the token ONLY from the gateway-forwarded {@code Authorization}
 * header; they never read a client's original token and never call Keycloak introspection.
 *
 * <p>This filter is the single, clearly-marked place where the future opaque->JWT phantom upgrade
 * will live: introspect the incoming opaque reference token at the gateway, then SWAP in the
 * internal JWT before forwarding. When that day comes, the change is made HERE ONLY — no product
 * changes. It is DISABLED now (ADR-3 rejects "phantom now"); enabling it is a gateway-only change.
 */
@Component
@ConfigurationProperties(prefix = "ecare.gateway.phantom")
public class PhantomIntrospectionFilter implements GlobalFilter, Ordered {

    /** DISABLED in Phase 1. Flipping this on is the entire phantom upgrade surface. */
    private boolean enabled = false;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!enabled) {
            // Phase 1: forward the already-validated JWT unchanged. Nothing to do.
            return chain.filter(exchange);
        }
        // ---------------------------------------------------------------------------------------
        // PHANTOM UPGRADE GOES HERE (future, gateway-only):
        //   1. Read the opaque reference token from the Authorization header.
        //   2. Introspect it (RFC 7662) against Keycloak, or resolve from the phantom store.
        //   3. Mint/fetch the internal JWT and REPLACE the Authorization header with it.
        //   4. chain.filter(mutatedExchange) so downstream products still see only a JWT.
        // No product changes — the seam is entirely inside this method.
        // ---------------------------------------------------------------------------------------
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        // After auth, immediately before routing/token-relay.
        return Ordered.LOWEST_PRECEDENCE - 2;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
