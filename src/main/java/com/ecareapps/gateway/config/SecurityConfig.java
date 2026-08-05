package com.ecareapps.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.SupplierReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Edge JWT enforcement (ADR-3, Phase 1 pure-JWT).
 *
 * <p>Every request except health probes and CORS pre-flight must carry a valid bearer token:
 * signature (cached JWKS) + {@code exp} + {@code iss}. Audience is NOT validated here because
 * it is per-route ({@code aud=ecarehealth} vs {@code aud=ecareadmin}); the
 * {@code RequireAudience} route filter enforces it against the validated token
 * (see {@link com.ecareapps.gateway.filter.RequireAudienceGatewayFilterFactory}).
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         ReactiveJwtDecoder jwtDecoder) {
        http
            // Stateless gateway: no server sessions, no CSRF tokens. CORS handled by CorsWebFilter bean.
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .cors(Customizer.withDefaults())
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .logout(ServerHttpSecurity.LogoutSpec::disable)
            .authorizeExchange(ex -> ex
                // Actuator health/readiness for the LB; nothing else is anonymous.
                .pathMatchers("/actuator/health", "/actuator/health/**").permitAll()
                // Pre-flight must not require auth (CorsWebFilter short-circuits it anyway).
                .pathMatchers(org.springframework.http.HttpMethod.OPTIONS).permitAll()
                .anyExchange().authenticated())
            .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtDecoder(jwtDecoder)))
            // 401 (not a redirect) on missing/invalid token — this is an API edge, not a browser app.
            .exceptionHandling(e -> e
                .authenticationEntryPoint((exchange, ex) -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                })
                .accessDeniedHandler((exchange, ex) -> {
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }));
        return http.build();
    }

    /**
     * Local JWT decoder. JWKS is fetched from {@code jwkSetUri} and cached in-process
     * (survives Keycloak outages); {@code iss}/{@code exp} validated on every request.
     *
     * <p>Wrapped in a {@link SupplierReactiveJwtDecoder} so the first JWKS fetch is lazy —
     * the gateway boots even if Keycloak is briefly unreachable at startup.
     */
    @Bean
    public ReactiveJwtDecoder jwtDecoder(GatewayJwtProperties props) {
        return new SupplierReactiveJwtDecoder(() -> {
            NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
                .withJwkSetUri(props.getJwkSetUri())
                .build();
            OAuth2TokenValidator<Jwt> validators = JwtValidators.createDefaultWithIssuer(props.getIssuer());
            decoder.setJwtValidator(validators);
            return decoder;
        });
    }
}
