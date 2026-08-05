package com.ecareapps.gateway;

import com.ecareapps.gateway.config.GatewayJwtProperties;
import com.ecareapps.gateway.config.RateLimitProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * eCareAuth front-door gateway (S2).
 *
 * <p>Single shared gateway (run >=2 replicas behind an LB for HA — never per-product).
 * Validates JWT locally at the edge via cached JWKS (ADR-3), routes host->product,
 * forwards the token unchanged, and applies all 8 VAPT Section B fixes centrally.
 */
@SpringBootApplication
@EnableConfigurationProperties({GatewayJwtProperties.class, RateLimitProperties.class})
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}