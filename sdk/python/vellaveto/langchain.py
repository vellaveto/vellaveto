"""
LangChain integration for Vellaveto.

Provides callback handlers and guards for integrating Vellaveto policy
enforcement into LangChain applications.

Example:
    from langchain.llms import OpenAI
    from langchain.chains import LLMChain
    from vellaveto import VellavetoClient
    from vellaveto.langchain import VellavetoCallbackHandler

    client = VellavetoClient(url="http://localhost:3000")
    handler = VellavetoCallbackHandler(client)

    llm = OpenAI()
    chain = LLMChain(llm=llm, callbacks=[handler])
"""

import logging
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from vellaveto.client import VellavetoClient, PolicyDenied, ApprovalRequired
from vellaveto.types import EvaluationContext, Verdict

logger = logging.getLogger(__name__)

# Check for LangChain availability
try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.agents import AgentAction, AgentFinish
    from langchain_core.outputs import LLMResult
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    # Define stub for type hints
    class BaseCallbackHandler:
        pass


class VellavetoCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler for Vellaveto policy enforcement.

    This handler intercepts tool calls and evaluates them against Vellaveto
    policies before execution. If a policy denies the action, the handler
    raises PolicyDenied to stop execution.

    Example:
        from vellaveto import VellavetoClient
        from vellaveto.langchain import VellavetoCallbackHandler

        client = VellavetoClient(url="http://localhost:3000")
        handler = VellavetoCallbackHandler(
            client=client,
            session_id="my-session",
            raise_on_deny=True,
        )

        # Use with any LangChain component
        agent = create_react_agent(..., callbacks=[handler])

    Attributes:
        client: VellavetoClient instance
        session_id: Session ID for stateful evaluation
        agent_id: Agent ID for agent-specific policies
        raise_on_deny: Whether to raise exceptions on policy denial
        log_evaluations: Whether to log all evaluations
    """

    def __init__(
        self,
        client: VellavetoClient,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        raise_on_deny: bool = True,
        log_evaluations: bool = True,
    ):
        if not HAS_LANGCHAIN:
            raise ImportError(
                "LangChain is required for VellavetoCallbackHandler. "
                "Install with: pip install langchain-core"
            )

        self.client = client
        self.session_id = session_id
        self.agent_id = agent_id
        self.raise_on_deny = raise_on_deny
        self.log_evaluations = log_evaluations
        self._call_chain: List[str] = []

    def _get_context(self) -> EvaluationContext:
        """Build evaluation context from handler state."""
        return EvaluationContext(
            session_id=self.session_id,
            agent_id=self.agent_id,
            call_chain=self._call_chain.copy(),
        )

    def _extract_tool_info(
        self,
        tool_name: str,
        tool_input: Union[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Extract tool, function, and parameters from LangChain tool call."""
        # Handle string inputs (some tools accept raw strings)
        if isinstance(tool_input, str):
            parameters = {"input": tool_input}
        else:
            parameters = tool_input

        # Extract paths and domains from common parameter patterns
        target_paths = []
        target_domains = []

        for key, value in parameters.items():
            if isinstance(value, str):
                # Common path parameter names
                if key in ("path", "file", "filename", "filepath", "directory", "dir"):
                    target_paths.append(value)
                # Common URL/domain parameter names
                elif key in ("url", "uri", "endpoint", "host", "domain"):
                    target_domains.append(value)
                # Check for URL patterns in any string value
                elif value.startswith(("http://", "https://", "ftp://")):
                    target_domains.append(value)

        return {
            "tool": tool_name,
            "function": tool_name,  # LangChain tools are typically single-function
            "parameters": parameters,
            "target_paths": target_paths,
            "target_domains": target_domains,
        }

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when a tool starts running.

        Evaluates the tool call against Vellaveto policies and raises
        PolicyDenied if the action is not allowed.
        """
        tool_name = serialized.get("name", "unknown")

        # Parse input - could be string or dict
        try:
            import json
            tool_input = json.loads(input_str) if isinstance(input_str, str) else input_str
        except (json.JSONDecodeError, TypeError):
            tool_input = input_str

        # Use inputs if provided (newer LangChain versions)
        if inputs:
            tool_input = inputs

        tool_info = self._extract_tool_info(tool_name, tool_input)

        if self.log_evaluations:
            logger.info(f"Evaluating tool call: {tool_name}")

        try:
            result = self.client.evaluate(
                tool=tool_info["tool"],
                function=tool_info["function"],
                parameters=tool_info["parameters"],
                target_paths=tool_info["target_paths"],
                target_domains=tool_info["target_domains"],
                context=self._get_context(),
            )

            # Track in call chain
            self._call_chain.append(tool_name)
            if len(self._call_chain) > 20:  # Limit chain length
                self._call_chain.pop(0)

            if self.log_evaluations:
                logger.info(f"Tool {tool_name} verdict: {result.verdict.value}")

            if result.verdict == Verdict.DENY:
                if self.raise_on_deny:
                    raise PolicyDenied(result.reason or "Policy denied", result.policy_id)
                else:
                    logger.warning(f"Tool {tool_name} denied: {result.reason}")

            elif result.verdict == Verdict.REQUIRE_APPROVAL:
                if self.raise_on_deny:
                    raise ApprovalRequired(
                        result.reason or "Approval required",
                        result.approval_id or "unknown",
                    )
                else:
                    logger.warning(
                        f"Tool {tool_name} requires approval: {result.reason}"
                    )

        except (PolicyDenied, ApprovalRequired):
            raise
        except Exception as e:
            logger.error(f"Vellaveto evaluation failed for {tool_name}: {e}")
            if self.raise_on_deny:
                # Fail-closed: treat errors as denials
                raise PolicyDenied(f"Evaluation failed: {e}")

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes running."""
        # Could add output scanning here in future
        pass

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors."""
        logger.error(f"Tool error: {error}")

    def on_agent_action(
        self,
        action: "AgentAction",
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """
        Called when an agent takes an action.

        This is called before on_tool_start for ReAct-style agents.
        """
        if self.log_evaluations:
            logger.debug(f"Agent action: {action.tool} with input: {action.tool_input}")

    def on_agent_finish(
        self,
        finish: "AgentFinish",
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an agent finishes."""
        if self.log_evaluations:
            logger.debug("Agent finished")

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts running."""
        # Could add prompt scanning here
        pass

    def on_llm_end(
        self,
        response: "LLMResult",
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM ends running."""
        # Could add response scanning here
        pass


class VellavetoToolGuard:
    """
    Decorator for guarding individual tools with Vellaveto policies.

    Example:
        from langchain.tools import tool
        from vellaveto import VellavetoClient
        from vellaveto.langchain import VellavetoToolGuard

        client = VellavetoClient(url="http://localhost:3000")
        guard = VellavetoToolGuard(client)

        @tool
        @guard("filesystem", "read_file")
        def read_file(path: str) -> str:
            '''Read a file from the filesystem.'''
            with open(path) as f:
                return f.read()

    Attributes:
        client: VellavetoClient instance
        session_id: Session ID for stateful evaluation
    """

    def __init__(
        self,
        client: VellavetoClient,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ):
        self.client = client
        self.session_id = session_id
        self.agent_id = agent_id

    def __call__(
        self,
        tool: str,
        function: Optional[str] = None,
        extract_paths: Optional[List[str]] = None,
        extract_domains: Optional[List[str]] = None,
    ):
        """
        Create a guard decorator for a specific tool.

        Args:
            tool: Tool name for policy evaluation
            function: Function name (defaults to decorated function name)
            extract_paths: Parameter names to extract as target_paths
            extract_domains: Parameter names to extract as target_domains
        """
        extract_paths = extract_paths or ["path", "file", "filepath"]
        extract_domains = extract_domains or ["url", "uri", "domain"]

        def decorator(func):
            import functools

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                func_name = function or func.__name__

                # Extract paths and domains from kwargs
                target_paths = []
                target_domains = []

                for key, value in kwargs.items():
                    if key in extract_paths and isinstance(value, str):
                        target_paths.append(value)
                    if key in extract_domains and isinstance(value, str):
                        target_domains.append(value)

                # Evaluate with Vellaveto
                context = EvaluationContext(
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                )

                self.client.evaluate_or_raise(
                    tool=tool,
                    function=func_name,
                    parameters=kwargs,
                    target_paths=target_paths,
                    target_domains=target_domains,
                    context=context,
                )

                # Policy allowed - execute the function
                return func(*args, **kwargs)

            return wrapper

        return decorator


def create_guarded_toolkit(
    client: VellavetoClient,
    toolkit: Any,
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> List[Any]:
    """
    Wrap all tools in a LangChain toolkit with Vellaveto guards.

    Example:
        from langchain_community.agent_toolkits import FileManagementToolkit
        from vellaveto import VellavetoClient
        from vellaveto.langchain import create_guarded_toolkit

        client = VellavetoClient(url="http://localhost:3000")
        toolkit = FileManagementToolkit()
        guarded_tools = create_guarded_toolkit(client, toolkit)

    Args:
        client: VellavetoClient instance
        toolkit: LangChain toolkit instance
        session_id: Session ID for stateful evaluation
        agent_id: Agent ID for agent-specific policies

    Returns:
        List of tools with Vellaveto guards applied
    """
    if not HAS_LANGCHAIN:
        raise ImportError("LangChain is required. Install with: pip install langchain")

    guard = VellavetoToolGuard(client, session_id=session_id, agent_id=agent_id)
    guarded_tools = []

    for tool in toolkit.get_tools():
        # Create a guarded version of the tool
        guarded_func = guard(
            tool=tool.name,
            function=tool.name,
        )(tool.func)

        # Create new tool with guarded function
        from langchain_core.tools import StructuredTool

        guarded_tool = StructuredTool(
            name=tool.name,
            description=tool.description,
            func=guarded_func,
            args_schema=getattr(tool, "args_schema", None),
        )
        guarded_tools.append(guarded_tool)

    return guarded_tools
