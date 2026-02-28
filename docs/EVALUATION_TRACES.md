# Evaluation Traces

Request a full decision trace showing which policies were checked and why.

## Usage

Add `?trace=true` to proxy requests:

```bash
curl -X POST "http://localhost:3001/mcp?trace=true" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"cmd":"ls"}}}'
```

## Trace Contents

The trace includes:
- Number of policies checked and matched
- Per-policy constraint evaluations (parameter tested, expected vs. actual, pass/fail)
- Final verdict with reason
- Evaluation duration in microseconds

## API

Use the `/api/evaluate` endpoint with `include_trace: true` in the request body:

```bash
curl -X POST http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $VELLAVETO_API_KEY" \
  -d '{
    "tool": "file",
    "function": "read",
    "parameters": {"path": "/tmp/test"},
    "include_trace": true
  }'
```

The response includes an `evaluation_trace` field with the full decision path.

## Execution Graphs

For visual call chain tracking, Vellaveto can export execution graphs in DOT (Graphviz) and JSON formats with color-coded verdicts, parent-child relationships, and graph statistics.

See the [API Reference](API.md) for execution graph endpoints.
