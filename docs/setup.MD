# Setup Guide

## Prerequisites

| Tool | Minimum Version | Purpose |
|---|---|---|
| Docker | 24.0 | Container runtime |
| Docker Compose | 2.20 | Multi-service orchestration |
| CMake | 3.25 | C++ build system |
| Ninja | 1.11 | C++ build backend |
| GCC / Clang | GCC 12 / Clang 15 | C++20 compiler |

## Environment Setup

Copy the example env file to the project root:

```bash
cp scripts/.env.example .env
```

Edit `.env` with your values. The defaults work for local
Docker Compose development without modification.

## Running with Docker Compose

```bash
# Start all services (RabbitMQ + MongoDB)
docker compose up

# Start in background
docker compose up -d

# View logs
docker compose logs -f

# Stop and remove containers
docker compose down
```

## Running the C++ Engine Locally

```bash
cd cpp-packet-engine

# Configure (dev preset — Debug, Ninja, exports compile_commands.json)
cmake --preset dev

# Build
cmake --build build/dev

# Run tests
ctest --test-dir build/dev --output-on-failure

# Run the engine (requires CAP_NET_RAW or sudo)
sudo ./build/dev/packet-engine
# OR use setcap for production:
# sudo setcap cap_net_raw,cap_net_admin+eip ./build/dev/packet-engine
# ./build/dev/packet-engine
```

## CMake Presets

| Preset | Build type | Use case |
|---|---|---|
| `dev` | Debug | Local development, IDE autocomplete |
| `docker` | Release | Inside Docker container |
| `ci` | Release | GitHub Actions CI pipeline |

## Resetting the Environment

```bash
# Drop MongoDB collections and purge RabbitMQ queues
./scripts/reset.sh
```

## Verifying the Stack

After `docker compose up`:

- RabbitMQ management UI: http://localhost:15672 (guest/guest)
- Spring Boot health: http://localhost:8080/health
- SSE stream: `./scripts/sse_tail.sh`
- MongoDB: `mongosh mongodb://localhost:27017/telemetry`

## Environment Variables

See `scripts/.env.example` for all variables with descriptions.
Content is filled in progressively as services are built.