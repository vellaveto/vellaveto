# Demo Scripts

Interactive demo showing VellaVeto blocking dangerous MCP tool calls in real time.

## Quick Demo

```bash
# Build the proxy
cargo build -p vellaveto-proxy

# Run the demo (uses a mock MCP server)
python3 demos/demo-client.py \
  target/debug/vellaveto-proxy --protect shield -- python3 demos/mock-mcp-server.py
```

You'll see VellaVeto block credential access and dangerous commands while allowing safe operations:

```
VellaVeto Shield Demo
Starting proxy: target/debug/vellaveto-proxy --protect shield -- python3 demos/mock-mcp-server.py

Connected to demo-server via VellaVeto proxy
Server exposes 4 tools

Read AWS credentials
  read_file(path="/home/user/.aws/credentials")
  BLOCKED — path blocked by credential-protection rule

Read SSH private key
  read_file(path="/home/user/.ssh/id_rsa")
  BLOCKED — path blocked by credential-protection rule

Destructive command
  execute(command="rm -rf /")
  BLOCKED — dangerous command blocked

Read a safe file
  read_file(path="/tmp/notes.txt")
  ALLOWED

List directory
  list_dir(path="/home/user/projects")
  ALLOWED
```

## Files

- `mock-mcp-server.py` — Minimal MCP server (stdio) that responds to tool calls
- `demo-client.py` — Interactive client that sends test requests and shows verdicts

## Requirements

- Python 3.8+
- Rust toolchain (to build `vellaveto-proxy`)
