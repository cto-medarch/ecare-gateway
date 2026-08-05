package com.ecareapps.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Defaults for the in-memory rate limiter (VAPT Section B.2, finding #5).
 *
 * <p>UAT uses an in-process token bucket (no Redis dependency). Per-route overrides come from the
 * {@code InMemoryRateLimit} filter args in application.yml.
 *
 * <p>TODO (production): replace with Redis-backed {@code RequestRateLimiter} so all replicas share
 * one bucket. See the commented dependency in pom.xml. The in-memory limiter is per-replica, which
 * is acceptable for single-node UAT only.
 */
@ConfigurationProperties(prefix = "ecare.gateway.ratelimit")
public class RateLimitProperties {

    /** Tokens (requests) refilled per second, per key. */
    private int replenishRate = 20;

    /** Maximum burst (bucket capacity), per key. */
    private int burstCapacity = 40;

    public int getReplenishRate() {
        return replenishRate;
    }

    public void setReplenishRate(int replenishRate) {
        this.replenishRate = replenishRate;
    }

    public int getBurstCapacity() {
        return burstCapacity;
    }

    public void setBurstCapacity(int burstCapacity) {
        this.burstCapacity = burstCapacity;
    }
}
