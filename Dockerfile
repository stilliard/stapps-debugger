# Build stage: compile a single static binary, with the templates and CSS built in
FROM rust:1-alpine AS build

RUN apk add --no-cache musl-dev

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY public ./public
COPY templates ./templates

RUN cargo build --release --locked

# Run stage: just the binary (no shell, no OS packages, nothing to patch)
FROM scratch

COPY --from=build /app/target/release/stapps-debugger /stapps-debugger

# run as "nobody" rather than root
USER 65534

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/stapps-debugger"]
