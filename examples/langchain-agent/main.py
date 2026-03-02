#!/usr/bin/env python3
"""
Vellaveto + LangChain Agent Example
====================================

Demonstrates how Vellaveto intercepts and evaluates LangChain tool calls
before they execute, blocking dangerous actions like reading credential
files or exfiltrating data to paste sites.

This example uses a mock LLM to keep the setup simple -- the important
part is the Vellaveto integration, which works identically with a real
LLM (OpenAI, Anthropic, etc.).

Prerequisites:
    pip install vellaveto-sdk langchain langchain-community

Start Vellaveto:
    vellaveto serve --config examples/langchain-agent/policy.toml --port 3000

Run this example:
    python examples/langchain-agent/main.py
"""

from vellaveto import VellavetoClient, PolicyDenied, Verdict
from vellaveto.types import EvaluationContext

# ---------------------------------------------------------------------------
# 1. Tool definitions -- simple file and web tools
# ---------------------------------------------------------------------------


def read_file(path: str) -> str:
    """Read a file from the filesystem and return its contents."""
    with open(path) as f:
        return f.read()


def fetch_url(url: str) -> str:
    """Fetch content from a URL (simulated for this example)."""
    return f"[Fetched content from {url}]"


# ---------------------------------------------------------------------------
# 2. Initialize the Vellaveto client
# ---------------------------------------------------------------------------

VELLAVETO_URL = "http://localhost:3000"

client = VellavetoClient(url=VELLAVETO_URL)


# ---------------------------------------------------------------------------
# 3. Guarded tool execution -- the core pattern
# ---------------------------------------------------------------------------

def execute_tool_guarded(
    tool_name: str,
    function_name: str,
    parameters: dict,
    *,
    target_paths: list[str] | None = None,
    target_domains: list[str] | None = None,
    context: EvaluationContext | None = None,
) -> str:
    """
    Evaluate a tool call against Vellaveto policies, then execute if allowed.

    This is the pattern you use in any agent framework: evaluate first,
    execute only if the verdict is Allow.
    """
    result = client.evaluate(
        tool=tool_name,
        function=function_name,
        parameters=parameters,
        target_paths=target_paths,
        target_domains=target_domains,
        context=context,
    )

    if result.verdict == Verdict.ALLOW:
        print(f"  [ALLOW] {tool_name}.{function_name}")
        print(f"          Policy: {result.policy_name or 'default'}")
        # Execute the actual tool
        if function_name == "read_file":
            return read_file(parameters["path"])
        elif function_name == "fetch_url":
            return fetch_url(parameters["url"])
        return "[unknown tool]"

    elif result.verdict == Verdict.DENY:
        print(f"  [DENY]  {tool_name}.{function_name}")
        print(f"          Reason: {result.reason}")
        print(f"          Policy: {result.policy_name or 'unknown'}")
        return f"BLOCKED: {result.reason}"

    elif result.verdict == Verdict.REQUIRE_APPROVAL:
        print(f"  [APPROVAL REQUIRED] {tool_name}.{function_name}")
        print(f"          Approval ID: {result.approval_id}")
        return f"PENDING APPROVAL: {result.approval_id}"

    return "[unexpected verdict]"


# ---------------------------------------------------------------------------
# 4. Simulate an agent conversation with tool calls
# ---------------------------------------------------------------------------

def run_agent_demo():
    """
    Simulate a LangChain-style agent that makes several tool calls.
    Vellaveto evaluates each call before execution.
    """
    print("=" * 70)
    print("Vellaveto + LangChain Agent Demo")
    print("=" * 70)

    # Create a session context for stateful policy evaluation
    ctx = EvaluationContext(
        session_id="demo-session-001",
        agent_id="langchain-file-agent",
    )

    # ------------------------------------------------------------------
    # Scenario 1: Read a safe file -- should be ALLOWED
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: Read a safe file (/tmp/notes.txt) ---")
    result = execute_tool_guarded(
        tool_name="filesystem",
        function_name="read_file",
        parameters={"path": "/tmp/notes.txt"},
        target_paths=["/tmp/notes.txt"],
        context=ctx,
    )
    print(f"  Result: {result[:80]}...")

    # ------------------------------------------------------------------
    # Scenario 2: Read AWS credentials -- should be DENIED
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Read AWS credentials (~/.aws/credentials) ---")
    result = execute_tool_guarded(
        tool_name="filesystem",
        function_name="read_file",
        parameters={"path": "/home/user/.aws/credentials"},
        target_paths=["/home/user/.aws/credentials"],
        context=ctx,
    )
    print(f"  Result: {result[:80]}")

    # ------------------------------------------------------------------
    # Scenario 3: Read SSH private key -- should be DENIED
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: Read SSH key (~/.ssh/id_rsa) ---")
    result = execute_tool_guarded(
        tool_name="filesystem",
        function_name="read_file",
        parameters={"path": "/home/user/.ssh/id_rsa"},
        target_paths=["/home/user/.ssh/id_rsa"],
        context=ctx,
    )
    print(f"  Result: {result[:80]}")

    # ------------------------------------------------------------------
    # Scenario 4: Read .env file -- should be DENIED
    # ------------------------------------------------------------------
    print("\n--- Scenario 4: Read .env file (project/.env) ---")
    result = execute_tool_guarded(
        tool_name="filesystem",
        function_name="read_file",
        parameters={"path": "/home/user/project/.env"},
        target_paths=["/home/user/project/.env"],
        context=ctx,
    )
    print(f"  Result: {result[:80]}")

    # ------------------------------------------------------------------
    # Scenario 5: Fetch from a legitimate URL -- should be ALLOWED
    # ------------------------------------------------------------------
    print("\n--- Scenario 5: Fetch from docs.python.org ---")
    result = execute_tool_guarded(
        tool_name="http",
        function_name="fetch_url",
        parameters={"url": "https://docs.python.org/3/tutorial/"},
        target_domains=["docs.python.org"],
        context=ctx,
    )
    print(f"  Result: {result[:80]}")

    # ------------------------------------------------------------------
    # Scenario 6: Exfiltrate to pastebin -- should be DENIED
    # ------------------------------------------------------------------
    print("\n--- Scenario 6: Exfiltrate data to pastebin.com ---")
    result = execute_tool_guarded(
        tool_name="http",
        function_name="fetch_url",
        parameters={"url": "https://pastebin.com/api/create"},
        target_domains=["pastebin.com"],
        context=ctx,
    )
    print(f"  Result: {result[:80]}")

    # ------------------------------------------------------------------
    # Scenario 7: Exfiltrate via webhook.site -- should be DENIED
    # ------------------------------------------------------------------
    print("\n--- Scenario 7: Exfiltrate data to webhook.site ---")
    result = execute_tool_guarded(
        tool_name="http",
        function_name="fetch_url",
        parameters={"url": "https://webhook.site/abc123"},
        target_domains=["webhook.site"],
        context=ctx,
    )
    print(f"  Result: {result[:80]}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    print("""
Vellaveto evaluated 7 tool calls:
  - 2 ALLOWED  (safe file read, legitimate URL)
  - 5 DENIED   (credentials, .env, exfiltration domains)

Every decision was logged to Vellaveto's tamper-evident audit trail.
The agent never touched a credential file or exfiltration endpoint.
""")


# ---------------------------------------------------------------------------
# 5. Bonus: Using the LangChain callback handler (for real agents)
# ---------------------------------------------------------------------------

def show_callback_handler_usage():
    """
    Show how you would integrate Vellaveto with a real LangChain agent
    using the callback handler. This code requires langchain and an LLM
    API key to actually run, but demonstrates the integration pattern.
    """
    print("=" * 70)
    print("LangChain Callback Handler Pattern (reference code)")
    print("=" * 70)

    code = '''
    from langchain.agents import create_react_agent, AgentExecutor
    from langchain.tools import tool
    from langchain_openai import ChatOpenAI
    from vellaveto import VellavetoClient
    from vellaveto.langchain import VellavetoCallbackHandler

    # 1. Initialize Vellaveto
    vellaveto = VellavetoClient(url="http://localhost:3000")
    handler = VellavetoCallbackHandler(
        client=vellaveto,
        session_id="prod-session-001",
        raise_on_deny=True,  # Raises PolicyDenied on blocked calls
    )

    # 2. Define your tools
    @tool
    def read_file(path: str) -> str:
        """Read a file from disk."""
        with open(path) as f:
            return f.read()

    @tool
    def web_search(query: str) -> str:
        """Search the web."""
        return f"Results for: {query}"

    # 3. Create the agent with Vellaveto callbacks
    llm = ChatOpenAI(model="gpt-4o")
    tools = [read_file, web_search]
    agent = create_react_agent(llm, tools, prompt=...)
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        callbacks=[handler],  # <-- Vellaveto evaluates every tool call
    )

    # 4. Run -- Vellaveto blocks dangerous calls automatically
    try:
        result = executor.invoke({"input": "Read ~/.aws/credentials"})
    except PolicyDenied as e:
        print(f"Agent blocked: {e.reason}")
    '''

    for line in code.strip().split("\n"):
        print(f"  {line}")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    # Check connectivity to Vellaveto before running
    try:
        health = client.health()
        print(f"Connected to Vellaveto at {VELLAVETO_URL}")
        print(f"  Status: {health.get('status', 'unknown')}\n")
    except Exception as e:
        print(f"ERROR: Cannot connect to Vellaveto at {VELLAVETO_URL}")
        print(f"  {e}\n")
        print("Start the server first:")
        print("  vellaveto serve --config examples/langchain-agent/policy.toml --port 3000")
        sys.exit(1)

    # Create a test file for Scenario 1
    import os
    os.makedirs("/tmp", exist_ok=True)
    with open("/tmp/notes.txt", "w") as f:
        f.write("These are my project notes. Nothing sensitive here.")

    # Run the demo
    run_agent_demo()

    # Show the callback handler pattern for reference
    print()
    show_callback_handler_usage()
