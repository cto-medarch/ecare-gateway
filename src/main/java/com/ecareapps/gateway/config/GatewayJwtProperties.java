package com.ecareapps.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Resource-server binding for the ecare-tenant realm.
 *
 * <p>{@code issuer} is the string stamped into the token {@code iss} claim and is what we
 * VALIDATE. {@code jwkSetUri} is the network endpoint we FETCH keys from — deliberately
 * decoupled so the container can reach Keycloak by its service name
 * ({@code http://ecare-keycloak:8080/...}) while still validating the public issuer
 * ({@code https://auth.ecareapps.com/...}). NimbusReactiveJwtDecoder caches the JWKS, so a
 * Keycloak blip does not invalidate already-issued tokens (ADR-3 "survive KC blips").
 */
@ConfigurationProperties(prefix = "ecare.gateway.jwt")
public class GatewayJwtProperties {

    /** Expected {@code iss} claim. Validated on every token. */
    private String issuer = "https://auth.ecareapps.com/realms/ecare-tenant";

    /** Where JWKS is actually fetched from (reachable from the gateway's network location). */
    private String jwkSetUri = "https://auth.ecareapps.com/realms/ecare-tenant/protocol/openid-connect/certs";

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getJwkSetUri() {
        return jwkSetUri;
    }

    public void setJwkSetUri(String jwkSetUri) {
        this.jwkSetUri = jwkSetUri;
    }
}
