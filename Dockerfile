# Step 1: Build the application using a valid Java 21 Maven image
FROM maven:3.9.6-eclipse-temurin-21 AS build
COPY . .
RUN mvn clean package -DskipTests

# Step 2: Run the application using a stable Java 21 runtime image
FROM eclipse-temurin:21-jre-jammy
COPY --from=build /target/piiguard-0.0.1-SNAPSHOT.jar piiguard.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","piiguard.jar"]