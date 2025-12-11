# Multi-Stage Dockerfile for Spring Boot Application (auth-service)

# --- STAGE 1: Build the JAR file ---
FROM eclipse-temurin:21-jdk-alpine as build
LABEL authors="MyLearn Senior Engineer"

# These are passed via docker-compose.yml or 'docker build --build-arg'
ARG GPR_USERNAME
ARG GPR_PASSWORD

# Set the working directory inside the container
WORKDIR /app

# Copy Maven Wrapper and POM first for caching
COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

# Create a temporary settings.xml file to hold the GPR credentials.
# Maven will use this to resolve the my-learn-common dependency.
RUN mkdir -p /root/.m2 \
    && echo '<settings><servers><server><id>github</id><username>${GPR_USERNAME}</username><password>${GPR_PASSWORD}</password></server></servers></settings>' > /root/.m2/settings.xml

# Copy the source code
COPY src /app/src

# Build the project
# Maven will now use the /root/.m2/settings.xml to resolve the 'my-learn-common' dependency.
RUN chmod +x mvnw \
    && ./mvnw clean package -DskipTests

# Find the built JAR file name dynamically
RUN mkdir -p target/dependency && (cd target/dependency; jar -xf ../*.jar)
# --- CLEANUP: Remove temporary settings file for security ---
RUN rm /root/.m2/settings.xml

# --- STAGE 2: Create the final, minimal runtime image ---
FROM eclipse-temurin:21-jre-alpine
LABEL authors="MyLearn Senior Engineer"

# Set the application owner user for security best practices
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Set the working directory for the application
WORKDIR /app

# Copy only the necessary layers from the build stage for an optimized JAR execution
COPY --from=build /app/target/*.jar /app/app.jar

# Expose the application port
EXPOSE 8080

# The command to run the application when the container starts
ENTRYPOINT ["java", "-jar", "/app/app.jar"]