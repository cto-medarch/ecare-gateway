package com.ecareapps.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Central per-route audience enforcement (contract §1: "aud names exactly ONE product").
 *
 * <p>Changed from the prior "defer to product" stance — the gateway now rejects at the edge if
 * the validated token's {@code aud} does not include the route's product id. Configured in
 * application.yml as {@code - RequireAudience=ecarehealth}.
 *
 * <p>Runs after Spring Security has populated the reactive security context, so the principal is
 * the already signature/exp/iss-validated {@link Jwt}.
 */
@Component
public class RequireAudienceGatewayFilterFactory
        extends AbstractGatewayFilterFactory<RequireAudienceGatewayFilterFactory.Config> {

    public RequireAudienceGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return List.of("audience");
    }

    @Override
    public GatewayFilter apply(Config config) {
        String required = config.getAudience();
        GatewayFilter filter = (exchange, chain) ->
            ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .filter(auth -> auth != null && auth.getPrincipal() instanceof Jwt)
                .flatMap(auth -> {
                    Jwt jwt = (Jwt) ((Authentication) auth).getPrincipal();
                    List<String> aud = jwt.getAudience();
                    if (aud != null && aud.contains(required)) {
                        return chain.filter(exchange);
                    }
                    return deny(exchange);
                })
                // No JWT in context (shouldn't happen behind authenticated()) => deny.
                .switchIfEmpty(deny(exchange));
        // Order after the security web filter chain; NettyRoutingFilter runs last anyway.
        return new OrderedGatewayFilter(filter, Ordered.LOWEST_PRECEDENCE - 1);
    }

    private reactor.core.publisher.Mono<Void> deny(org.springframework.web.server.ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }

    public static class Config {
        /** Product id this route requires in the token's {@code aud} claim. */
        private String audience;

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }
    }
}
