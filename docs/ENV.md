# Environment Variables

Environment variables override values set in the config file.

## Core

| Variable | Default | Description |
|----------|---------|-------------|
| `VELLAVETO_API_KEY` | *(required)* | Bearer token for all authenticated endpoints |
| `VELLAVETO_SIGNING_KEY` | *(auto-generated)* | Hex-encoded 32-byte Ed25519 seed for audit checkpoints |
| `VELLAVETO_CHECKPOINT_INTERVAL` | `300` | Seconds between automatic audit checkpoints (0 to disable) |
| `VELLAVETO_TRUSTED_PROXIES` | *(none)* | Comma-separated trusted proxy IPs for X-Forwarded-For |
| `VELLAVETO_CORS_ORIGINS` | *(localhost)* | Comma-separated allowed CORS origins (`*` for any) |
| `VELLAVETO_LOG_MAX_SIZE` | `104857600` | Max audit log size in bytes before rotation (0 to disable) |
| `VELLAVETO_NO_CANONICALIZE` | `false` | Disable JSON-RPC re-serialization before forwarding |
| `VELLAVETO_TRUSTED_KEY` | *(none)* | Pin a trusted Ed25519 public key for checkpoint verification |
| `VELLAVETO_AGENT_ID` | *(none)* | Agent identity for stdio proxy mode |
| `VELLAVETO_LICENSE_KEY` | *(none)* | Ed25519-signed license key (overrides config file) |
| `VELLAVETO_LICENSE_PUBLIC_KEY` | *(none)* | Hex-encoded Ed25519 public key (32 bytes = 64 hex chars) for license verification |
| `RUST_LOG` | `info` | Log level filter (`tracing` / `env_logger` syntax) |

## Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `VELLAVETO_RATE_EVALUATE` | `1000` | Max evaluations per second |
| `VELLAVETO_RATE_EVALUATE_BURST` | `50` | Evaluation burst capacity |
| `VELLAVETO_RATE_ADMIN` | `20` | Max admin requests per second |
| `VELLAVETO_RATE_ADMIN_BURST` | `5` | Admin burst capacity |
| `VELLAVETO_RATE_READONLY` | `200` | Max read-only requests per second |
| `VELLAVETO_RATE_READONLY_BURST` | `20` | Read-only burst capacity |
| `VELLAVETO_RATE_PER_IP` | `100` | Max requests per IP per second |
| `VELLAVETO_RATE_PER_IP_BURST` | `10` | Per-IP burst capacity |
| `VELLAVETO_RATE_PER_IP_MAX_CAPACITY` | `100000` | Max tracked IPs for rate limiting |
| `VELLAVETO_RATE_PER_PRINCIPAL` | `50` | Max requests per principal per second |
| `VELLAVETO_RATE_PER_PRINCIPAL_BURST` | `10` | Per-principal burst capacity |
