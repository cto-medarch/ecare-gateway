package com.ecareapps.gateway.filter;

import com.ecareapps.gateway.config.RateLimitProperties;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * VAPT Section B.2 (finding #5) — per-IP + per-route rate limiting.
 *
 * <p>In-memory token bucket for UAT (no Redis). Key = {@code routeId|clientIp}, so each client is
 * throttled independently on each route (auth/token-adjacent routes can be tightened via args).
 * Rejects over-limit requests with 429 and a {@code Retry-After} hint.
 *
 * <p>Configured as {@code - InMemoryRateLimit=20,40} (replenishRate, burstCapacity); omit args to
 * use {@link RateLimitProperties} defaults.
 *
 * <p>TODO (production): swap for Redis {@code RequestRateLimiter} — this bucket is per-replica.
 */
@Component
public class InMemoryRateLimitGatewayFilterFactory
        extends AbstractGatewayFilterFactory<InMemoryRateLimitGatewayFilterFactory.Config> {

    private final RateLimitProperties defaults;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public InMemoryRateLimitGatewayFilterFactory(RateLimitProperties defaults) {
        super(Config.class);
        this.defaults = defaults;
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return List.of("replenishRate", "burstCapacity");
    }

    @Override
    public GatewayFilter apply(Config config) {
        int rate = config.getReplenishRate() > 0 ? config.getReplenishRate() : defaults.getReplenishRate();
        int burst = config.getBurstCapacity() > 0 ? config.getBurstCapacity() : defaults.getBurstCapacity();

        return (exchange, chain) -> {
            String key = keyFor(exchange);
            Bucket bucket = buckets.computeIfAbsent(key, k -> new Bucket(rate, burst));
            if (bucket.tryConsume()) {
                return chain.filter(exchange);
            }
            exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            exchange.getResponse().getHeaders().set("Retry-After", "1");
            return exchange.getResponse().setComplete();
        };
    }

    private String keyFor(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        String routeId = route != null ? route.getId() : "unknown-route";
        return routeId + "|" + clientIp(exchange);
    }

    /** Trust X-Forwarded-For's first hop (we sit behind an LB); fall back to socket address. */
    private String clientIp(ServerWebExchange exchange) {
        String xff = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        var remote = exchange.getRequest().getRemoteAddress();
        return remote != null ? remote.getAddress().getHostAddress() : "unknown-ip";
    }

    /** Lazy-refill token bucket. Thread-safe via synchronized consume. */
    private static final class Bucket {
        private final double refillPerNano;
        private final double capacity;
        private double tokens;
        private long lastRefillNanos;

        Bucket(int replenishRatePerSec, int burstCapacity) {
            this.refillPerNano = replenishRatePerSec / 1_000_000_000d;
            this.capacity = burstCapacity;
            this.tokens = burstCapacity;
            this.lastRefillNanos = System.nanoTime();
        }

        synchronized boolean tryConsume() {
            long now = System.nanoTime();
            double refill = (now - lastRefillNanos) * refillPerNano;
            if (refill > 0) {
                tokens = Math.min(capacity, tokens + refill);
                lastRefillNanos = now;
            }
            if (tokens >= 1d) {
                tokens -= 1d;
                return true;
            }
            return false;
        }
    }

    public static class Config {
        private int replenishRate;
        private int burstCapacity;

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
}
