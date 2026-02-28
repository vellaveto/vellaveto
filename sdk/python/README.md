# Vellaveto Python SDK

Python SDK for the [Vellaveto MCP Firewall](https://github.com/paolovella/vellaveto) - AI agent security policy enforcement.

## Installation

```bash
# Basic installation
pip install vellaveto-sdk

# With LangChain support
pip install vellaveto-sdk[langchain]

# With LangGraph support
pip install vellaveto-sdk[langgraph]

# Full installation
pip install vellaveto-sdk[all]
```

## Quick Start

### Direct API Usage

```python
from vellaveto import VellavetoClient, Verdict

client = VellavetoClient(url="http://localhost:3000", api_key="your-key")

# Evaluate a tool call
result = client.evaluate(
    tool="filesystem",
    function="read_file",
    parameters={"path": "/etc/passwd"}
)

if result.verdict == Verdict.ALLOW:
    # Proceed with tool call
    content = read_file("/etc/passwd")
elif result.verdict == Verdict.DENY:
    print(f"Blocked: {result.reason}")
elif result.verdict == Verdict.REQUIRE_APPROVAL:
    print(f"Needs approval: {result.approval_id}")
```

### With Exception Handling

```python
from vellaveto import VellavetoClient, PolicyDenied, ApprovalRequired

client = VellavetoClient(url="http://localhost:3000")

try:
    client.evaluate_or_raise(
        tool="http",
        function="fetch",
        parameters={"url": "https://evil.com/exfil"}
    )
    # Allowed - proceed
except PolicyDenied as e:
    print(f"Blocked by policy: {e.reason}")
except ApprovalRequired as e:
    print(f"Needs approval: {e.approval_id}")
```

### Async Usage

```python
from vellaveto import AsyncVellavetoClient

async with AsyncVellavetoClient(url="http://localhost:3000") as client:
    result = await client.evaluate(
        tool="bash",
        function="execute",
        parameters={"command": "rm -rf /"}
    )
```

## LangChain Integration

### Callback Handler

The `VellavetoCallbackHandler` automatically intercepts and evaluates all tool calls:

```python
from langchain.agents import create_react_agent
from langchain_openai import ChatOpenAI
from vellaveto import VellavetoClient
from vellaveto.langchain import VellavetoCallbackHandler

client = VellavetoClient(url="http://localhost:3000")
handler = VellavetoCallbackHandler(
    client=client,
    session_id="my-session",
    raise_on_deny=True,
)

llm = ChatOpenAI()
agent = create_react_agent(llm, tools, callbacks=[handler])

# All tool calls will be evaluated by Vellaveto
result = agent.invoke({"input": "Read the file /etc/passwd"})
```

### Tool Decorator

Guard individual tools with the `@guard` decorator:

```python
from langchain.tools import tool
from vellaveto import VellavetoClient
from vellaveto.langchain import VellavetoToolGuard

client = VellavetoClient(url="http://localhost:3000")
guard = VellavetoToolGuard(client)

@tool
@guard("filesystem", "read_file")
def read_file(path: str) -> str:
    """Read a file from the filesystem."""
    with open(path) as f:
        return f.read()
```

### Wrap Existing Toolkits

```python
from langchain_community.agent_toolkits import FileManagementToolkit
from vellaveto import VellavetoClient
from vellaveto.langchain import create_guarded_toolkit

client = VellavetoClient(url="http://localhost:3000")
toolkit = FileManagementToolkit()
guarded_tools = create_guarded_toolkit(client, toolkit)
```

## LangGraph Integration

### Vellaveto Node

Add a vellaveto evaluation node to your graph:

```python
from langgraph.graph import StateGraph, END
from vellaveto import VellavetoClient
from vellaveto.langgraph import create_vellaveto_node, VellavetoState

client = VellavetoClient(url="http://localhost:3000")
vellaveto_node = create_vellaveto_node(client, on_deny="block")

class MyState(VellavetoState):
    messages: list
    # ... your fields

graph = StateGraph(MyState)
graph.add_node("plan", plan_node)
graph.add_node("vellaveto", vellaveto_node)
graph.add_node("tools", tool_node)

graph.add_edge("plan", "vellaveto")
graph.add_conditional_edges(
    "vellaveto",
    lambda s: "blocked" if s.get("tool_blocked") else "allowed",
    {"blocked": END, "allowed": "tools"},
)
```

### Guarded Tool Node

Combine tool execution with policy evaluation:

```python
from langgraph.graph import StateGraph
from vellaveto import VellavetoClient
from vellaveto.langgraph import create_vellaveto_tool_node

client = VellavetoClient(url="http://localhost:3000")
tool_node = create_vellaveto_tool_node(client, [read_file, write_file])

graph = StateGraph(MyState)
graph.add_node("tools", tool_node)  # Policy evaluation + execution
```

## Parameter Redaction

Strip sensitive parameter values before they transit the network to Vellaveto:

```python
from vellaveto import VellavetoClient, ParameterRedactor

# Keys-only (default): redacts values for known sensitive parameter names
redactor = ParameterRedactor()

# Values: also scans string values for secret patterns (sk-..., ghp_..., JWTs)
redactor = ParameterRedactor(mode="values")

# All: redacts every parameter value (sends only keys to Vellaveto)
redactor = ParameterRedactor(mode="all")

# Custom sensitive keys (added to defaults)
redactor = ParameterRedactor(extra_keys={"internal_token", "vault_path"})

client = VellavetoClient(url="http://localhost:3000", redactor=redactor)

# api_key value is replaced with "[REDACTED]" before sending
client.evaluate(
    tool="http",
    function="fetch",
    parameters={"url": "https://api.example.com", "api_key": "sk-secret123"},
)
```

## Configuration

### Client Options

```python
client = VellavetoClient(
    url="http://localhost:3000",  # Vellaveto server URL
    api_key="your-api-key",       # API key for authentication
    timeout=30.0,                  # Request timeout in seconds
    verify_ssl=True,               # Verify SSL certificates
    redactor=ParameterRedactor(),  # Client-side parameter redaction (optional)
)
```

### Evaluation Context

Provide context for stateful policy evaluation:

```python
from vellaveto.types import EvaluationContext

context = EvaluationContext(
    session_id="user-session-123",
    agent_id="my-agent",
    tenant_id="tenant-abc",
    call_chain=["tool1", "tool2"],
    metadata={"user": "alice"},
)

result = client.evaluate(
    tool="filesystem",
    function="write_file",
    parameters={"path": "/tmp/output.txt", "content": "data"},
    context=context,
)
```

## API Reference

### VellavetoClient

| Method | Description |
|--------|-------------|
| `evaluate()` | Evaluate a tool call against policies |
| `evaluate_or_raise()` | Evaluate and raise on denial |
| `health()` | Check server health |
| `list_policies()` | List configured policies |
| `reload_policies()` | Reload policies from config |
| `get_pending_approvals()` | Get pending approval requests |
| `resolve_approval()` | Approve or deny a request |
| `discover()` | Search the tool discovery index |
| `discovery_stats()` | Get discovery index statistics |
| `discovery_reindex()` | Rebuild discovery IDF weights |
| `discovery_tools()` | List indexed tools with optional filters |
| `projector_models()` | List supported projector model families |
| `project_schema()` | Project canonical schema for a model family |

### Types

| Type | Description |
|------|-------------|
| `Verdict` | Policy decision (ALLOW, DENY, REQUIRE_APPROVAL) |
| `Action` | Tool call representation |
| `EvaluationResult` | Policy evaluation result |
| `EvaluationContext` | Context for stateful evaluation |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `VellavetoError` | Base exception |
| `PolicyDenied` | Action denied by policy |
| `ApprovalRequired` | Action requires human approval |
| `ConnectionError` | Failed to connect to server |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy vellaveto

# Linting
ruff check vellaveto
```

## License

See [LICENSE](LICENSE) and [LICENSING.md](../../LICENSING.md) for package and repository licensing details.
