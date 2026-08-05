# syntax=docker/dockerfile:1

# ── Build stage ──────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
# Cache dependencies first (pom rarely changes vs. source).
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B clean package -DskipTests

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Run as non-root.
RUN addgroup -S ecare && adduser -S ecare -G ecare
USER ecare

COPY --from=build /build/target/ecareauth-gateway-*.jar app.jar

EXPOSE 8081

# Container-aware JVM; fail fast on OOM.
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"

# Liveness/readiness via actuator (compose/K8s probe hits this).
HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=30s \
  CMD wget -qO- http://localhost:8081/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
