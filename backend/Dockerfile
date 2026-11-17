FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN mvn -B -ntp package

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S training && adduser -S training -G training && mkdir -p /app/data /app/identity /app/keys && chown training:training /app/data /app/identity /app/keys && chmod 700 /app/identity /app/keys
WORKDIR /app
COPY --from=build /workspace/target/deep-cyber-sample-backend-1.0.0.jar /app/app.jar
USER training
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:8080/api/health | grep -q '"status":"UP"' || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
