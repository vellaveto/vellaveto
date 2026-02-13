# Sentinel Python SDK

Python SDK for the [Sentinel MCP Firewall](https://github.com/paolovella/sentinel) - AI agent security policy enforcement.

## Installation

```bash
# Basic installation
pip install sentinel-sdk

# With LangChain support
pip install sentinel-sdk[langchain]

# With LangGraph support
pip install sentinel-sdk[langgraph]

# Full installation
pip install sentinel-sdk[all]
```

## Quick Start

### Direct API Usage

```python
from sentinel import SentinelClient, Verdict

client = SentinelClient(url="http://localhost:8080", api_key="your-key")

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
from sentinel import SentinelClient, PolicyDenied, ApprovalRequired

client = SentinelClient(url="http://localhost:8080")

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
from sentinel import AsyncSentinelClient

async with AsyncSentinelClient(url="http://localhost:8080") as client:
    result = await client.evaluate(
        tool="bash",
        function="execute",
        parameters={"command": "rm -rf /"}
    )
```

## LangChain Integration

### Callback Handler

The `SentinelCallbackHandler` automatically intercepts and evaluates all tool calls:

```python
from langchain.agents import create_react_agent
from langchain_openai import ChatOpenAI
from sentinel import SentinelClient
from sentinel.langchain import SentinelCallbackHandler

client = SentinelClient(url="http://localhost:8080")
handler = SentinelCallbackHandler(
    client=client,
    session_id="my-session",
    raise_on_deny=True,
)

llm = ChatOpenAI()
agent = create_react_agent(llm, tools, callbacks=[handler])

# All tool calls will be evaluated by Sentinel
result = agent.invoke({"input": "Read the file /etc/passwd"})
```

### Tool Decorator

Guard individual tools with the `@guard` decorator:

```python
from langchain.tools import tool
from sentinel import SentinelClient
from sentinel.langchain import SentinelToolGuard

client = SentinelClient(url="http://localhost:8080")
guard = SentinelToolGuard(client)

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
from sentinel import SentinelClient
from sentinel.langchain import create_guarded_toolkit

client = SentinelClient(url="http://localhost:8080")
toolkit = FileManagementToolkit()
guarded_tools = create_guarded_toolkit(client, toolkit)
```

## LangGraph Integration

### Sentinel Node

Add a sentinel evaluation node to your graph:

```python
from langgraph.graph import StateGraph, END
from sentinel import SentinelClient
from sentinel.langgraph import create_sentinel_node, SentinelState

client = SentinelClient(url="http://localhost:8080")
sentinel_node = create_sentinel_node(client, on_deny="block")

class MyState(SentinelState):
    messages: list
    # ... your fields

graph = StateGraph(MyState)
graph.add_node("plan", plan_node)
graph.add_node("sentinel", sentinel_node)
graph.add_node("tools", tool_node)

graph.add_edge("plan", "sentinel")
graph.add_conditional_edges(
    "sentinel",
    lambda s: "blocked" if s.get("tool_blocked") else "allowed",
    {"blocked": END, "allowed": "tools"},
)
```

### Guarded Tool Node

Combine tool execution with policy evaluation:

```python
from langgraph.graph import StateGraph
from sentinel import SentinelClient
from sentinel.langgraph import create_sentinel_tool_node

client = SentinelClient(url="http://localhost:8080")
tool_node = create_sentinel_tool_node(client, [read_file, write_file])

graph = StateGraph(MyState)
graph.add_node("tools", tool_node)  # Policy evaluation + execution
```

## Configuration

### Client Options

```python
client = SentinelClient(
    url="http://localhost:8080",  # Sentinel server URL
    api_key="your-api-key",       # API key for authentication
    timeout=30.0,                  # Request timeout in seconds
    verify_ssl=True,               # Verify SSL certificates
)
```

### Evaluation Context

Provide context for stateful policy evaluation:

```python
from sentinel.types import EvaluationContext

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

### SentinelClient

| Method | Description |
|--------|-------------|
| `evaluate()` | Evaluate a tool call against policies |
| `evaluate_or_raise()` | Evaluate and raise on denial |
| `health()` | Check server health |
| `list_policies()` | List configured policies |
| `reload_policies()` | Reload policies from config |
| `get_pending_approvals()` | Get pending approval requests |
| `resolve_approval()` | Approve or deny a request |

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
| `SentinelError` | Base exception |
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
mypy sentinel

# Linting
ruff check sentinel
```

## License

AGPL-3.0 (dual license available) - see [LICENSING.md](../../LICENSING.md) for details.
