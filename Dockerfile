FROM maven as build

WORKDIR /app
COPY pom.xml ./
RUN mvn dependency:resolve
COPY src ./src
RUN mvn package spring-boot:repackage -Dmaven.test.skip

FROM gcr.io/distroless/java21
WORKDIR /app

COPY --from=build /app/target/k8s-probe-1.0-SNAPSHOT.jar ./
COPY examples ./examples

CMD ["k8s-probe-1.0-SNAPSHOT.jar"]
