"""
LangGraph integration for Sentinel.

Provides nodes and state management for integrating Sentinel policy
enforcement into LangGraph agent workflows.

Example:
    from langgraph.graph import StateGraph
    from sentinel import SentinelClient
    from sentinel.langgraph import create_sentinel_node, SentinelState

    client = SentinelClient(url="http://localhost:3000")
    sentinel_node = create_sentinel_node(client)

    # Add to your graph
    graph = StateGraph(SentinelState)
    graph.add_node("sentinel", sentinel_node)
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TypedDict, Annotated

from sentinel.client import SentinelClient, PolicyDenied, ApprovalRequired
from sentinel.types import EvaluationContext, EvaluationResult, Verdict

logger = logging.getLogger(__name__)

# Check for LangGraph availability
try:
    from langgraph.graph import StateGraph
    from langgraph.prebuilt import ToolNode
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False


class SentinelState(TypedDict, total=False):
    """
    State schema for Sentinel integration in LangGraph.

    Add these fields to your graph state to enable Sentinel integration.

    Example:
        from typing import TypedDict, List
        from sentinel.langgraph import SentinelState

        class MyAgentState(SentinelState):
            messages: List[BaseMessage]
            # ... your other state fields
    """

    # Sentinel evaluation results
    sentinel_verdict: Optional[str]
    sentinel_reason: Optional[str]
    sentinel_policy_id: Optional[str]
    sentinel_approval_id: Optional[str]

    # Context tracking
    sentinel_session_id: Optional[str]
    sentinel_agent_id: Optional[str]
    sentinel_call_chain: List[str]

    # Pending tool call (set before sentinel node, cleared after)
    pending_tool_name: Optional[str]
    pending_tool_input: Optional[Dict[str, Any]]

    # Block flag (set by sentinel node if tool is denied)
    tool_blocked: bool


def create_sentinel_node(
    client: SentinelClient,
    on_deny: str = "block",
    on_approval_required: str = "block",
) -> callable:
    """
    Create a LangGraph node for Sentinel policy evaluation.

    This node should be placed before the tool execution node in your graph.
    It evaluates the pending tool call and either allows it to proceed or
    blocks execution.

    Example:
        from langgraph.graph import StateGraph, END
        from sentinel import SentinelClient
        from sentinel.langgraph import create_sentinel_node

        client = SentinelClient(url="http://localhost:3000")
        sentinel_node = create_sentinel_node(client, on_deny="block")

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

    Args:
        client: SentinelClient instance
        on_deny: Action on denial - "block" (default) or "continue"
        on_approval_required: Action on approval required - "block" or "continue"

    Returns:
        A LangGraph node function
    """

    def sentinel_node(state: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate pending tool call against Sentinel policies."""
        tool_name = state.get("pending_tool_name")
        tool_input = state.get("pending_tool_input", {})

        if not tool_name:
            # No pending tool call - pass through
            return {"tool_blocked": False}

        # Build context from state
        context = EvaluationContext(
            session_id=state.get("sentinel_session_id"),
            agent_id=state.get("sentinel_agent_id"),
            call_chain=state.get("sentinel_call_chain", []),
        )

        # Extract paths and domains from tool input
        target_paths = []
        target_domains = []

        if isinstance(tool_input, dict):
            for key, value in tool_input.items():
                if isinstance(value, str):
                    if key in ("path", "file", "filepath", "directory"):
                        target_paths.append(value)
                    elif key in ("url", "uri", "endpoint", "domain"):
                        target_domains.append(value)
                    elif value.startswith(("http://", "https://")):
                        target_domains.append(value)

        try:
            result = client.evaluate(
                tool=tool_name,
                function=tool_name,
                parameters=tool_input if isinstance(tool_input, dict) else {"input": tool_input},
                target_paths=target_paths,
                target_domains=target_domains,
                context=context,
            )

            # Update call chain
            call_chain = state.get("sentinel_call_chain", []).copy()
            call_chain.append(tool_name)
            if len(call_chain) > 20:
                call_chain.pop(0)

            # Determine if blocked
            blocked = False
            if result.verdict == Verdict.DENY and on_deny == "block":
                blocked = True
                logger.warning(f"Tool {tool_name} blocked by policy: {result.reason}")
            elif result.verdict == Verdict.REQUIRE_APPROVAL and on_approval_required == "block":
                blocked = True
                logger.warning(f"Tool {tool_name} requires approval: {result.reason}")

            return {
                "sentinel_verdict": result.verdict.value,
                "sentinel_reason": result.reason,
                "sentinel_policy_id": result.policy_id,
                "sentinel_approval_id": result.approval_id,
                "sentinel_call_chain": call_chain,
                "tool_blocked": blocked,
            }

        except Exception as e:
            logger.error(f"Sentinel evaluation failed: {e}")
            # Fail-closed
            return {
                "sentinel_verdict": "deny",
                "sentinel_reason": f"Evaluation error: {e}",
                "tool_blocked": on_deny == "block",
            }

    return sentinel_node


def create_sentinel_tool_node(
    client: SentinelClient,
    tools: List[Any],
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> callable:
    """
    Create a LangGraph tool node with built-in Sentinel evaluation.

    This combines tool execution with policy evaluation in a single node,
    eliminating the need for a separate sentinel node.

    Example:
        from langgraph.graph import StateGraph
        from langchain_core.tools import tool
        from sentinel import SentinelClient
        from sentinel.langgraph import create_sentinel_tool_node

        @tool
        def read_file(path: str) -> str:
            '''Read a file.'''
            return open(path).read()

        client = SentinelClient(url="http://localhost:3000")
        tool_node = create_sentinel_tool_node(client, [read_file])

        graph = StateGraph(MyState)
        graph.add_node("tools", tool_node)

    Args:
        client: SentinelClient instance
        tools: List of LangChain tools
        session_id: Session ID for stateful evaluation
        agent_id: Agent ID for agent-specific policies

    Returns:
        A LangGraph tool node function with Sentinel guards
    """
    if not HAS_LANGGRAPH:
        raise ImportError(
            "LangGraph is required. Install with: pip install langgraph"
        )

    # Import here to avoid circular imports
    from sentinel.langchain import SentinelCallbackHandler

    handler = SentinelCallbackHandler(
        client=client,
        session_id=session_id,
        agent_id=agent_id,
        raise_on_deny=True,
    )

    # Create base tool node
    base_node = ToolNode(tools)

    def guarded_tool_node(state: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tools with Sentinel policy evaluation."""
        # Get messages from state
        messages = state.get("messages", [])

        if not messages:
            return state

        last_message = messages[-1]

        # Check if it's a tool call message
        if not hasattr(last_message, "tool_calls") or not last_message.tool_calls:
            return state

        # Evaluate each tool call
        for tool_call in last_message.tool_calls:
            tool_name = tool_call.get("name", "unknown")
            tool_input = tool_call.get("args", {})

            context = EvaluationContext(
                session_id=session_id or state.get("sentinel_session_id"),
                agent_id=agent_id or state.get("sentinel_agent_id"),
                call_chain=state.get("sentinel_call_chain", []),
            )

            # Extract paths/domains
            target_paths = []
            target_domains = []
            if isinstance(tool_input, dict):
                for key, value in tool_input.items():
                    if isinstance(value, str):
                        if key in ("path", "file", "filepath"):
                            target_paths.append(value)
                        elif key in ("url", "uri", "domain"):
                            target_domains.append(value)

            try:
                client.evaluate_or_raise(
                    tool=tool_name,
                    function=tool_name,
                    parameters=tool_input,
                    target_paths=target_paths,
                    target_domains=target_domains,
                    context=context,
                )
            except PolicyDenied as e:
                # Return denial as tool message
                from langchain_core.messages import ToolMessage

                return {
                    "messages": [
                        ToolMessage(
                            content=f"Tool call blocked by security policy: {e.reason}",
                            tool_call_id=tool_call.get("id", ""),
                            name=tool_name,
                        )
                    ]
                }
            except ApprovalRequired as e:
                from langchain_core.messages import ToolMessage

                return {
                    "messages": [
                        ToolMessage(
                            content=f"Tool call requires approval (id: {e.approval_id}): {e.reason}",
                            tool_call_id=tool_call.get("id", ""),
                            name=tool_name,
                        )
                    ]
                }

        # All tools allowed - execute with base node
        return base_node(state)

    return guarded_tool_node


class SentinelCheckpoint:
    """
    LangGraph checkpoint wrapper with Sentinel session tracking.

    Automatically manages session state across graph checkpoints.

    Example:
        from langgraph.checkpoint import MemorySaver
        from sentinel import SentinelClient
        from sentinel.langgraph import SentinelCheckpoint

        client = SentinelClient(url="http://localhost:3000")
        checkpoint = SentinelCheckpoint(client, MemorySaver())

        graph = graph.compile(checkpointer=checkpoint)
    """

    def __init__(
        self,
        client: SentinelClient,
        base_checkpoint: Any,
    ):
        self.client = client
        self.base = base_checkpoint
        self._sessions: Dict[str, str] = {}

    def get(self, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get checkpoint state."""
        state = self.base.get(config)
        if state:
            # Inject session ID if not present
            thread_id = config.get("configurable", {}).get("thread_id", "default")
            if "sentinel_session_id" not in state:
                state["sentinel_session_id"] = f"langgraph-{thread_id}"
        return state

    def put(self, config: Dict[str, Any], state: Dict[str, Any]) -> None:
        """Save checkpoint state."""
        self.base.put(config, state)
