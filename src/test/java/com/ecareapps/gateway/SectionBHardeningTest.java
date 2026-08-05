package com.ecareapps.gateway;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * VAPT Section B acceptance test — asserts all 8 hardening items are present at the edge, plus
 * central audience enforcement and Keycloak-outage survival (cached JWKS).
 *
 * <p>Self-contained: an RSA keypair signs test tokens; a {@link MockWebServer} serves the JWKS
 * (so no live Keycloak is needed) and a second serves a stub downstream that echoes a Set-Cookie.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(OrderAnnotation.class)
class SectionBHardeningTest {

    private static final String ISSUER = "https://auth.ecareapps.com/realms/ecare-tenant";

    private static RSAKey rsaKey;
    private static MockWebServer jwks;
    private static MockWebServer downstream;

    @LocalServerPort
    int port;

    @BeforeAll
    static void startServers() throws Exception {
        rsaKey = new RSAKeyGenerator(2048).keyID("test-key-1").generate();

        // JWKS server — returns our public key set for any path. Fresh response each call so the
        // body buffer is never drained across requests.
        jwks = new MockWebServer();
        String jwksJson = new com.nimbusds.jose.jwk.JWKSet(rsaKey.toPublicJWK()).toString();
        jwks.setDispatcher(freshEachCall(() -> new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody(jwksJson)));
        jwks.start();

        // Downstream stub — 200 + a Set-Cookie WITHOUT HttpOnly/Secure (so we can assert the
        // gateway adds them). Echoes back so token relay is observable via recorded requests.
        downstream = new MockWebServer();
        downstream.setDispatcher(freshEachCall(() -> new MockResponse()
            .setResponseCode(200)
            .setHeader("Set-Cookie", "SESSION=abc123; Path=/")
            .setBody("{\"ok\":true}")));
        downstream.start();
    }

    @AfterAll
    static void stopServers() throws Exception {
        if (downstream != null) downstream.shutdown();
        if (jwks != null && jwks.getPort() > 0) {
            try { jwks.shutdown(); } catch (Exception ignored) { }
        }
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry reg) {
        reg.add("ecare.gateway.jwt.issuer", () -> ISSUER);
        reg.add("ecare.gateway.jwt.jwk-set-uri", () -> jwks.url("/certs").toString());
        reg.add("ecare.gateway.routes.ecarehealth-uri", () -> downstream.url("/").toString());
        reg.add("ecare.gateway.routes.ecareadmin-uri", () -> downstream.url("/").toString());
    }

    private WebTestClient client() {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    // ── B.4–B.8: security headers present even on an unauthenticated 401 ──────────────────────
    @Test
    @Order(1)
    void securityHeadersPresentOnEveryResponse() {
        client().get().uri("/anything")
            .header(HttpHeaders.HOST, "api.ecarehealth.com")
            .exchange()
            .expectStatus().isUnauthorized()   // no token
            .expectHeader().valueEquals("X-XSS-Protection", "1; mode=block")            // #5
            .expectHeader().exists("Content-Security-Policy")                            // #6
            .expectHeader().valueMatches("Content-Security-Policy", "default-src 'self'.*")
            .expectHeader().valueEquals("Strict-Transport-Security",
                "max-age=31536000; includeSubDomains")                                  // #7
            .expectHeader().valueEquals("X-Content-Type-Options", "nosniff");
    }

    // ── Valid token (aud=ecarehealth) routes; token relayed; Set-Cookie hardened (B.4 + B.8) ──
    @Test
    @Order(2)
    void validAudienceRoutesAndHardensCookies() throws Exception {
        String token = token(List.of("ecarehealth"), 300);

        client().get().uri("/patients")
            .header(HttpHeaders.HOST, "api.ecarehealth.com")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .exchange()
            .expectStatus().isOk()
            .expectHeader().value(HttpHeaders.SET_COOKIE, v -> {
                assertThat(v.toLowerCase()).contains("httponly");   // #4
                assertThat(v.toLowerCase()).contains("secure");     // #8
            });

        // Token relay (phantom seam): downstream received the SAME token, unchanged.
        RecordedRequest recorded = downstream.takeRequest();
        assertThat(recorded.getHeader(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + token);
    }

    // ── Central audience enforcement: wrong aud rejected at the edge (403) ────────────────────
    @Test
    @Order(3)
    void wrongAudienceRejectedAtEdge() {
        String token = token(List.of("ecareadmin"), 300); // wrong product for the ecarehealth route
        client().get().uri("/patients")
            .header(HttpHeaders.HOST, "api.ecarehealth.com")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .exchange()
            .expectStatus().isForbidden();
    }

    // ── Expired token rejected (401) ──────────────────────────────────────────────────────────
    @Test
    @Order(4)
    void expiredTokenRejected() {
        String expired = token(List.of("ecarehealth"), -60); // exp in the past
        client().get().uri("/patients")
            .header(HttpHeaders.HOST, "api.ecarehealth.com")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + expired)
            .exchange()
            .expectStatus().isUnauthorized();
    }

    // ── B.3: disallowed HTTP method -> 405 ───────────────────────────────────────────────────
    @Test
    @Order(5)
    void disallowedMethodRejected() {
        String token = token(List.of("ecareadmin"), 300);
        client().method(HttpMethod.DELETE).uri("/tenants")   // admin route allows only GET,POST
            .header(HttpHeaders.HOST, "admin-api.ecareapps.com")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .exchange()
            .expectStatus().isEqualTo(405)
            .expectHeader().exists("Allow");
    }

    // ── B.1: CORS strict allow-list — allowed origin reflected, disallowed origin rejected ────
    @Test
    @Order(6)
    void corsReflectsOnlyAllowedOrigins() {
        // Allowed origin (Keycloak webOrigin) is reflected on pre-flight.
        client().options().uri("/patients")
            .header(HttpHeaders.HOST, "api.ecarehealth.com")
            .header(HttpHeaders.ORIGIN, "http://localhost:3000")
            .header("Access-Control-Request-Method", "GET")
            .exchange()
            .expectHeader().valueEquals("Access-Control-Allow-Origin", "http://localhost:3000");

        // Disallowed origin is NOT reflected (rejected pre-flight, no ACAO header).
        client().options().uri("/patients")
            .header(HttpHeaders.HOST, "api.ecarehealth.com")
            .header(HttpHeaders.ORIGIN, "http://evil.example.com")
            .header("Access-Control-Request-Method", "GET")
            .exchange()
            .expectHeader().doesNotExist("Access-Control-Allow-Origin");
    }

    // ── ADR-3: Keycloak outage — cached JWKS still validates already-issuable tokens ──────────
    // Runs last: by now the decoder has fetched+cached the JWKS at least once.
    @Test
    @Order(99)
    void survivesKeycloakOutage() throws Exception {
        jwks.shutdown(); // simulate Keycloak/JWKS endpoint down

        String token = token(List.of("ecarehealth"), 300);
        client().get().uri("/patients")
            .header(HttpHeaders.HOST, "api.ecarehealth.com")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .exchange()
            .expectStatus().isOk();   // validated from cache, no live KC call

        downstream.takeRequest(); // drain
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────

    /** Build a signed access token matching the contract shape; {@code ttlSeconds} may be negative. */
    private String token(List<String> audience, long ttlSeconds) {
        try {
            long now = System.currentTimeMillis();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("a3f1c2e4-0000-0000-0000-000000000000")
                .audience(audience)
                .claim("azp", "ecarehealth-spa")
                .claim("tenant", "jupiter")
                .claim("tenant_id", "b7d9-0000")
                .claim("org", "jupiter")
                .claim("persona", List.of("provider"))
                .claim("scope", "openid profile")
                .issueTime(new Date(now))
                .expirationTime(new Date(now + ttlSeconds * 1000))
                .build();
            SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims);
            jwt.sign(new RSASSASigner(rsaKey.toPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("failed to mint test token", e);
        }
    }

    private static Dispatcher freshEachCall(java.util.function.Supplier<MockResponse> factory) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return factory.get();
            }
        };
    }
}
