# Stage 1: Build Stage
FROM maven:3.9-eclipse-temurin-8 AS build

WORKDIR /app

COPY . .

RUN mvn clean package

# Stage 2: Runtime Stage
FROM tomcat:8.5.88-jdk8-corretto

# Copy the WAR file built in the previous stage
COPY --from=build /app/target/*.war /usr/local/tomcat/webapps/

# Copy the pre-prepared tomcat-users.xml to set up user roles
COPY default-tomcat.xml /usr/local/tomcat/conf/tomcat-users.xml

# CMD to start Tomcat
CMD ["catalina.sh", "run"]
