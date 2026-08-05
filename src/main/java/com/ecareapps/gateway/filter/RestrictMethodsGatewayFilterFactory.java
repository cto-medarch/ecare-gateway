package com.ecareapps.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * VAPT Section B.3 (finding #7) — restrict each route to the HTTP methods its product needs;
 * reject anything else with 405 (and an {@code Allow} header).
 *
 * <p>Used instead of a bare {@code Method=} predicate so a disallowed verb returns a clean
 * 405 rather than falling through to a 404. Configured as
 * {@code - RestrictMethods=GET,POST,PUT,PATCH,DELETE}.
 */
@Component
public class RestrictMethodsGatewayFilterFactory
        extends AbstractGatewayFilterFactory<RestrictMethodsGatewayFilterFactory.Config> {

    public RestrictMethodsGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return List.of("methods");
    }

    @Override
    public GatewayFilter apply(Config config) {
        Set<String> allowed = config.getMethods().stream()
            .map(m -> m.trim().toUpperCase())
            .collect(Collectors.toCollection(HashSet::new));
        // OPTIONS must always pass for CORS pre-flight.
        allowed.add("OPTIONS");
        String allowHeader = String.join(", ", allowed);

        return (exchange, chain) -> {
            HttpMethod method = exchange.getRequest().getMethod();
            if (method != null && allowed.contains(method.name())) {
                return chain.filter(exchange);
            }
            exchange.getResponse().setStatusCode(HttpStatus.METHOD_NOT_ALLOWED);
            exchange.getResponse().getHeaders().set("Allow", allowHeader);
            return exchange.getResponse().setComplete();
        };
    }

    public static class Config {
        /** Methods this route permits (comma-separated in YAML). */
        private List<String> methods;

        public List<String> getMethods() {
            return methods;
        }

        public void setMethods(List<String> methods) {
            this.methods = methods;
        }

        public void setMethods(String csv) {
            this.methods = Arrays.asList(csv.split(","));
        }
    }
}
