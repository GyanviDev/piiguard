# Step 1: Build the application
FROM maven:3.8.5-openjdk-21 AS build
COPY . .
RUN mvn clean package -DskipTests

# Step 2: Run the application
FROM openjdk:21-jdk-slim
COPY --from=build /target/piiguard-0.0.1-SNAPSHOT.jar piiguard.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","piiguard.jar"]