# LangChain Agent + Vellaveto Example

A runnable example showing how Vellaveto intercepts LangChain agent tool calls
and enforces security policies before execution.

## What This Demonstrates

1. **Credential protection** -- Blocks access to `~/.aws/`, `~/.ssh/`, `.env` files
2. **Exfiltration prevention** -- Blocks requests to paste sites and webhook services
3. **Safe operations pass through** -- Reading `/tmp` files and fetching legitimate URLs are allowed
4. **Audit trail** -- Every decision (allow and deny) is logged

## Prerequisites

```bash
# Install the Vellaveto server (Rust binary)
cargo install vellaveto-server --path vellaveto-server

# Install the Python SDK
pip install vellaveto-sdk

# Optional: for the callback handler pattern with a real LLM
pip install vellaveto-sdk[langchain] langchain langchain-community langchain-openai
```

## Running the Example

### 1. Start Vellaveto with the example policy

```bash
vellaveto serve --config examples/langchain-agent/policy.toml --port 3000
```

### 2. Run the agent demo

```bash
python examples/langchain-agent/main.py
```

## Expected Output

```
Connected to Vellaveto at http://localhost:3000
  Status: ok

======================================================================
Vellaveto + LangChain Agent Demo
======================================================================

--- Scenario 1: Read a safe file (/tmp/notes.txt) ---
  [ALLOW] filesystem.read_file
          Policy: Default allow
  Result: These are my project notes. Nothing sensitive here....

--- Scenario 2: Read AWS credentials (~/.aws/credentials) ---
  [DENY]  filesystem.read_file
          Reason: Denied by parameter constraint: /home/user/.aws/credentials
          Policy: Block credential files
  Result: BLOCKED: Denied by parameter constraint: /home/user/.aws/credentials

--- Scenario 3: Read SSH key (~/.ssh/id_rsa) ---
  [DENY]  filesystem.read_file
          Reason: Denied by parameter constraint: /home/user/.ssh/id_rsa
          Policy: Block credential files
  Result: BLOCKED: Denied by parameter constraint: /home/user/.ssh/id_rsa

--- Scenario 4: Read .env file (project/.env) ---
  [DENY]  filesystem.read_file
          Reason: Denied by parameter constraint: /home/user/project/.env
          Policy: Block credential files
  Result: BLOCKED: Denied by parameter constraint: /home/user/project/.env

--- Scenario 5: Fetch from docs.python.org ---
  [ALLOW] http.fetch_url
          Policy: Default allow
  Result: [Fetched content from https://docs.python.org/3/tutorial/]...

--- Scenario 6: Exfiltrate data to pastebin.com ---
  [DENY]  http.fetch_url
          Reason: Denied by parameter constraint: pastebin.com
          Policy: Block exfiltration domains
  Result: BLOCKED: Denied by parameter constraint: pastebin.com

--- Scenario 7: Exfiltrate data to webhook.site ---
  [DENY]  http.fetch_url
          Reason: Denied by parameter constraint: webhook.site
          Policy: Block exfiltration domains
  Result: BLOCKED: Denied by parameter constraint: webhook.site

======================================================================
Summary
======================================================================

Vellaveto evaluated 7 tool calls:
  - 2 ALLOWED  (safe file read, legitimate URL)
  - 5 DENIED   (credentials, .env, exfiltration domains)

Every decision was logged to Vellaveto's tamper-evident audit trail.
The agent never touched a credential file or exfiltration endpoint.
```

## Policy Explained

The `policy.toml` file defines three layers:

| Priority | Policy | Action |
|----------|--------|--------|
| 300 | Block credential files | Deny access to `~/.aws/`, `~/.ssh/`, `.env`, etc. |
| 200 | Block exfiltration domains | Deny requests to pastebin.com, webhook.site, etc. |
| 1 | Default allow | Allow everything not explicitly blocked |

Higher priority policies are evaluated first. If a call matches a deny rule at
priority 300, it is blocked regardless of the allow rule at priority 1.

## Integration Patterns

### Direct evaluation (shown in `main.py`)

Call `client.evaluate()` before executing each tool. You get full control over
the verdict handling:

```python
from vellaveto import VellavetoClient, Verdict

client = VellavetoClient(url="http://localhost:3000")

result = client.evaluate(
    tool="filesystem",
    function="read_file",
    parameters={"path": "/home/user/.aws/credentials"},
    target_paths=["/home/user/.aws/credentials"],
)

if result.verdict == Verdict.DENY:
    print(f"Blocked: {result.reason}")
```

### LangChain callback handler (for real agents)

Attach `VellavetoCallbackHandler` to your agent and it evaluates every tool
call automatically:

```python
from vellaveto import VellavetoClient
from vellaveto.langchain import VellavetoCallbackHandler

client = VellavetoClient(url="http://localhost:3000")
handler = VellavetoCallbackHandler(client=client, raise_on_deny=True)

agent = create_react_agent(llm, tools, callbacks=[handler])
```

### evaluate_or_raise (exception-based)

If you prefer exceptions over inspecting verdicts:

```python
from vellaveto import VellavetoClient, PolicyDenied

client = VellavetoClient(url="http://localhost:3000")

try:
    client.evaluate_or_raise(
        tool="filesystem",
        function="read_file",
        parameters={"path": "/home/user/.ssh/id_rsa"},
    )
    # If we get here, the call is allowed
except PolicyDenied as e:
    print(f"Blocked by policy: {e.reason}")
```

## Files

| File | Description |
|------|-------------|
| `main.py` | Runnable demo with 7 tool call scenarios |
| `policy.toml` | Vellaveto policy (credentials + exfiltration blocking) |
| `README.md` | This file |

## Next Steps

- Try modifying `policy.toml` to add your own rules
- See `examples/presets/` for production-ready policy templates
- Read `sdk/python/README.md` for the full SDK API reference
- See `docs/QUICKSTART.md` for integration guides for other frameworks
