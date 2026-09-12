FROM maven:3.9.16-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml ./
COPY src ./src
RUN mvn -q clean package -DskipTests

FROM eclipse-temurin:21.0.12_8-jre
WORKDIR /app
RUN useradd --system --uid 10001 appuser && mkdir -p /data && chown -R appuser:appuser /data
COPY --from=build /app/target/*.jar app.jar
USER appuser
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
