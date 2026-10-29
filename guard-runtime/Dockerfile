FROM maven:3.9.16-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml ./
COPY src ./src
RUN mvn -q clean package -DskipTests

FROM eclipse-temurin:21.0.12_8-jre
WORKDIR /app
RUN useradd --system --uid 10001 appuser && mkdir -p /data/replay /data/activity /data/policy && chown -R appuser:appuser /data
COPY --from=build /app/target/*.jar app.jar
# Seed for the first start; afterwards the dashboard's Policy tab publishes versions under /data/policy. Mount another
# file over GUARD_RUNTIME_POLICY_FILE (or edit the policy in the dashboard) to allow your own security API host.
COPY policy/privacy-guard-policy.json /app/policy/seed.json
ENV GUARD_RUNTIME_POLICY_FILE=/app/policy/seed.json \
    GUARD_RUNTIME_POLICY_DIR=/data/policy
USER appuser
VOLUME ["/data"]
EXPOSE 3101
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
