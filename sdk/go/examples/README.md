# Vellaveto Go SDK Examples

Runnable examples demonstrating common integration patterns with the Vellaveto Go SDK.

## Prerequisites

A running Vellaveto server. By default the examples connect to `http://localhost:3000`.
Override with environment variables:

```bash
export VELLAVETO_URL=http://localhost:3000
export VELLAVETO_API_KEY=your-api-key
```

## Examples

### basic

Demonstrates core SDK usage: create a client, check server health, evaluate a
tool call, and handle Allow / Deny / RequireApproval verdicts. Also shows the
`EvaluateOrError` convenience method with typed error handling and how to list
loaded policies.

```bash
cd basic
go run .
```

### middleware

Shows how to build an HTTP middleware that enforces Vellaveto policies before
forwarding requests to an upstream handler. The middleware extracts tool-call
metadata from custom request headers, evaluates the action, and returns
403 Forbidden when the policy engine denies the call. Errors from the policy
engine result in 503 Service Unavailable (fail-closed).

```bash
cd middleware
go run .

# In another terminal:
curl -H "X-Tool-Name: read_file" \
     -H "X-Tool-Target-Path: /data/report.csv" \
     http://localhost:8080/api/tool-call

curl -H "X-Tool-Name: exec_command" \
     -H "X-Tool-Function: shell" \
     http://localhost:8080/api/tool-call
```

## Adding New Examples

1. Create a new directory under `examples/`.
2. Add a `main.go` with a `package main` and a `main()` function.
3. Update this README with a description and run instructions.
