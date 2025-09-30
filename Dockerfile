# ---- Build Stage ----
FROM rust:bookworm AS builder
WORKDIR /app

# aws-lc-sys deps
RUN apt update && \
    apt install -y build-essential cmake clang pkg-config

# Copy in the Cargo.toml files so that dependency resolution works
#COPY Cargo.toml Cargo.lock ./
## Create dummy source to cache dependencies
#RUN mkdir -p src && \
#    echo "fn main() {}" > src/main.rs
#RUN cargo build --release || true

# Copy source and build
# Now only copy sources
#COPY src/ src/
COPY . .
RUN cargo build --release

#FROM gcr.io/distroless/cc-debian12
ENV RUST_LOG=info
#COPY --from=builder /app/target/release/chiastamp /chiastamp
#CMD ["/chiastamp"]
CMD ["/app/target/release/chiastamp"]