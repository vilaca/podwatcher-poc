FROM gradle:8.5-jdk21 as build

WORKDIR /app
COPY build.gradle settings.gradle* ./
COPY gradle ./gradle
COPY src ./src
RUN gradle build -x test --no-daemon

FROM gcr.io/distroless/java21
WORKDIR /app

COPY --from=build /app/build/libs/*.jar ./app.jar
COPY examples ./examples

CMD ["app.jar"]
