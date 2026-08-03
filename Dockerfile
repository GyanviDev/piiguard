# ══════════════════════════════════════════════════════════════════════════════
#  PII Guard — Java proxy
#
#  Problems with the previous three-line version:
#    * `COPY . .` with no WORKDIR copied the project into the container ROOT (/),
#      leaving build artefacts scattered at top level.
#    * The whole source tree was copied before dependency resolution, so ANY source
#      edit invalidated the layer cache and Maven re-downloaded every dependency —
#      turning a one-line change into a multi-minute build.
#    * It ran as root. A remote-code-execution bug in any dependency would then be
#      root inside the container, which is one namespace escape away from root on
#      the host.
#    * No healthcheck, so an orchestrator could not tell a started container from a
#      working one, and would route traffic to a process still loading its NER model.
# ══════════════════════════════════════════════════════════════════════════════

# ── Stage 1: dependencies ─────────────────────────────────────────────────────
FROM maven:3.9.6-eclipse-temurin-21 AS deps
WORKDIR /build
# Only the POM, so this layer is rebuilt when dependencies change and not when code does.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline

# ── Stage 2: build ────────────────────────────────────────────────────────────
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /build
COPY --from=deps /root/.m2 /root/.m2
COPY pom.xml .
COPY src ./src
RUN mvn -B -q clean package -DskipTests

# ── Stage 3: runtime ──────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-jammy

RUN groupadd --system piiguard \
 && useradd --system --gid piiguard --home /app --shell /usr/sbin/nologin piiguard \
 && mkdir -p /app/data \
 && chown -R piiguard:piiguard /app

WORKDIR /app
COPY --from=build --chown=piiguard:piiguard /build/target/piiguard-*.jar app.jar

USER piiguard

EXPOSE 8081

# MaxRAMPercentage rather than a fixed -Xmx: the JVM then sizes the heap from the
# container's cgroup limit, so the same image behaves correctly on a 512 MB free tier
# and on a 4 GB node without being rebuilt.
ENV JAVA_OPTS="-XX:MaxRAMPercentage=70 -XX:+ExitOnOutOfMemoryError"

# Readiness comes from Spring Boot's own probe, so the container is only considered
# healthy once the NER model has loaded and the datasource is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD wget -q --spider http://localhost:8081/actuator/health/readiness || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
