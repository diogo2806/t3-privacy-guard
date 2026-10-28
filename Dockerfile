# Privacy Guard application: the dashboard is built and packaged inside the backend jar, so one container serves
# both. guard-runtime is the second service and has its own image (guard-runtime/Dockerfile).
FROM node:22.20.0-alpine3.22 AS dashboard
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM maven:3.9.16-eclipse-temurin-21 AS build
WORKDIR /app
COPY backend/pom.xml ./
COPY backend/src ./src
COPY --from=dashboard /frontend/dist ./src/main/resources/static
RUN mvn -q clean package -DskipTests

FROM eclipse-temurin:21.0.12_8-jre
WORKDIR /app
RUN useradd --system --uid 10001 appuser && mkdir -p /data && chown -R appuser:appuser /data
COPY --from=build /app/target/*.jar app.jar
USER appuser
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
