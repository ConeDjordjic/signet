# Build stage
FROM rust:1.87-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    pkg-config \
    libssl-dev \
    curl \
    ca-certificates \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests and build files first for dependency caching
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto

# Create dummy source for dependency build
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs

# Build dependencies (cached layer)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src

# Build the application
RUN touch src/main.rs src/lib.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash signet
USER signet

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/signet /app/signet

# Expose HTTP and gRPC ports
EXPOSE 8080 50051

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["/app/signet"]
