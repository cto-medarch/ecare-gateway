# 04 — Spring Cloud Gateway (ecareauth-gateway)

Front door. Validates JWT locally, routes to products over HTTP. Phantom-ready seam (ADR-3).
Separate repo. Run **≥2 replicas** behind LB (HA). One shared gateway, not per-product.

---

## Stack
- Spring Cloud Gateway (reactive), Java 21, Spring Boot 3.x.
- Spring Security OAuth2 Resource Server (JWT, cached JWKS from `ecare-tenant`).

## Responsibilities (Phase 1 — pure JWT)
1. Validate JWT: signature (cached JWKS), `exp`, `iss`, **and `aud`** — no per-request Keycloak call.
2. Route by host to the correct product.
3. Forward the validated token unchanged (`Authorization` header).
4. Apply all 8 VAPT Section B fixes at the edge (see below).
5. Rate limiting + structured logging (no PHI/tokens in logs).

## The phantom seam (DO NOT VIOLATE)
- Products receive the token **only** from the gateway-forwarded header.
- Products never read a client's original token, never call Keycloak introspection themselves.
- Later phantom upgrade = add introspection+swap **at the gateway only**; products unchanged.
- Placeholder filter `PhantomIntrospectionFilter` (disabled) marks the seam.

## Routing (host-based)
```
api.ecarehealth.com       -> ecarehealth-api    (require aud=ecarehealth)
admin-api.ecareapps.com   -> eCareAdmin stub    (require aud=ecareadmin)
```
- Issuer: `https://auth.ecareapps.com/realms/ecare-tenant`
- JWKS URI: `https://auth.ecareapps.com/realms/ecare-tenant/protocol/openid-connect/certs`
- eCareAdmin real build is S3. S2 uses a stub (health/echo) so routing + auth are testable now.

## Audience enforcement
Gateway rejects at edge if `aud` does not match the route's product.
(Changed from prior "defer to product" — we enforce centrally now.)

## VAPT Section B — all 8 applied centrally
1. CORS — strict allow-list only (no `+`, no broad wildcards). Reflect only allowed origins.
2. Rate limiting — per-IP + per-route. Redis-backed (in-memory for UAT, TODO Redis).
3. HTTP methods — restrict per route; reject others (405).
4. Cookie HttpOnly — verify/enforce on pass-through Set-Cookie.
5. `X-XSS-Protection: 1; mode=block` on all responses.
6. CSP — strict `default-src` on all responses (login theme origin allowed).
7. HSTS — `Strict-Transport-Security` max-age + includeSubDomains on all responses.
8. Cookie Secure — verify/enforce on pass-through Set-Cookie.
   (4–8 as one global response-header filter.)

## Tasks
- [ ] Resource-server config: JWKS URI + issuer above.
- [ ] Two host-based routes (config-as-code) with per-route aud check.
- [ ] Token relay filter (forward as-is).
- [ ] Global filters: security headers, CORS, method restriction, phantom seam.
- [ ] Rate-limit + structured logging (assert no PHI/tokens in logs).
- [ ] Degraded-mode documented (serve valid tokens during KC blip; block new logins).
- [ ] Dockerfile + compose entry (join S1 network to reach Keycloak).

## Acceptance criteria
- [ ] Valid JWT (aud=ecarehealth) routes to eCareHealth; wrong/expired rejected at edge.
- [ ] admin-api route reachable via stub with aud=ecareadmin.
- [ ] KC outage: already-issued tokens still validated (JWKS cached); test simulates JWKS down.
- [ ] All 8 Section B headers/policies present (SectionBHardeningTest).
- [ ] No token or PHI in gateway logs (test).