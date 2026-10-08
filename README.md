# SentinelRS

**From Cloud Events to Attack Stories.**  
*Real-time cloud threat detection, attack-chain reconstruction, and autonomous response.*

---

## Overview

**SentinelRS** is a high-performance cloud security platform engineered in **Rust**. It continuously ingests AWS telemetry, detects suspicious activities using rule engines and behavioural baselines, reconstructs multi-stage lateral movement attack graphs using `petgraph`, calculates explainable risk scores, and orchestrates safe autonomous containment actions.

---

## Key Features

- **Rust-First Core Engine**: High throughput and sub-millisecond detection latency powered by `tokio` and `axum`.
- **Attack Graph Reconstruction**: Transforms isolated CloudTrail events into causal, temporal, and identity-linked attack trees.
- **MITRE ATT&CK Matrix**: Automated mapping across Initial Access, Privilege Escalation, Persistence, Defense Evasion, and Exfiltration.
- **Explainable Risk Scoring**: Deconstructs threat scores (0–100) into transparent, auditable factors.
- **Autonomous Response Orchestrator**: Safe by design with Simulation Mode by default and live AWS remediation gates.
- **Attack Simulation Lab**: Built-in interactive test harness to simulate full multi-stage kill chains without needing live AWS credentials.
- **Modern Clean Light UI**: Emerald and white SOC console with landing page, left taskbar navigation, and interactive graph visualizations.

---

## Step-by-Step Instructions: Running with Docker

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running on your system.
- Docker Compose v2+ (included by default with Docker Desktop).

---

### Step 1: Clone the Repository & Navigate to Project Directory

```bash
git clone https://github.com/sentinelrs/sentinelrs.git
cd "CPI Project"
```

---

### Step 2: Environment Configuration (Optional)

You can copy the example environment file if you wish to customize port or credentials:

```bash
# On Linux/macOS
cp .env.example .env

# On Windows PowerShell
Copy-Item .env.example .env
```

*(Default values in `docker-compose.yml` work out-of-the-box without editing).*

---

### Step 3: Build & Start All Services

Run the following command to build the Rust server image and start all containers (PostgreSQL database, Rust backend API, and Nginx web server):

```bash
docker compose up -d --build
```

> **Note**: The first build may take a few minutes as Cargo compiles all Rust workspace crates in release mode.

---

### Step 4: Verify Container Health & Status

Check that all 3 services (`sentinel-postgres`, `sentinel-server`, and `sentinel-ui`) are running healthy:

```bash
docker compose ps
```

To view real-time logs from the Rust backend:

```bash
docker compose logs -f sentinel-backend
```

---

### Step 5: Access the Web Application & APIs

Once the containers are up, access the platform in your browser:

| Component | URL | Description |
| :--- | :--- | :--- |
| **SentinelRS Landing & SOC UI** | [http://localhost:3000](http://localhost:3000) | Full web console with Landing page & Taskbar |
| **Axum REST API** | [http://localhost:8080/api/events](http://localhost:8080/api/events) | Backend REST endpoints |
| **API Health Check** | [http://localhost:8080/api/health](http://localhost:8080/api/health) | Backend health status |
| **WebSocket Stream** | `ws://localhost:8080/ws/events` | Real-time live event streaming |

---

### Step 6: Stopping & Managing the Containers

- **Stop all services:**
  ```bash
  docker compose down
  ```

- **Stop services and remove stored database volumes:**
  ```bash
  docker compose down -v
  ```

- **Rebuild after making code changes:**
  ```bash
  docker compose up -d --build
  ```

---

## Local Development (Without Docker)

If you prefer to run SentinelRS directly with Cargo:

```bash
# 1. Start PostgreSQL (e.g., via Docker)
docker compose up -d sentinel-postgres

# 2. Run backend server
cargo run --bin sentinel-server

# 3. Open frontend
# Open frontend/index.html in your browser or run a static web server:
cd frontend
python -m http.server 3000
```

---

## Repository Structure

```text
├── Cargo.toml               # Workspace manifest
├── Dockerfile               # Multi-stage production container
├── docker-compose.yml       # Orchestration (PostgreSQL, Backend, UI)
├── crates/
│   ├── sentinel-core/       # Domain models & event schema
│   ├── sentinel-ingest/     # Synthetic generator & dataset replay
│   ├── sentinel-normalizer/ # CloudTrail parsing & enrichment
│   ├── sentinel-detection/  # Rule engine (15+ detectors)
│   ├── sentinel-correlation/# Multi-dimensional correlation & graph
│   ├── sentinel-risk/       # Transparent risk decomposition
│   ├── sentinel-mitre/      # ATT&CK taxonomy mapper
│   ├── sentinel-response/   # Containment engine & audit logs
│   ├── sentinel-storage/    # State caching & database migrations
│   └── sentinel-api/        # Axum REST & WebSocket endpoints
├── services/
│   └── sentinel-server/     # Production server binary
├── frontend/                # Real-time light green & white SOC UI
└── data/                    # Attack scenarios and sample CloudTrail datasets
```
