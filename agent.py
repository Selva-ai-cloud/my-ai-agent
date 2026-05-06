"""
SIEM Incident Handling Agent (LangChain + MCP)
===============================================
This agent:
1. Connects to the SIEM MCP server via subprocess (stdio transport)
2. Discovers available tools automatically
3. Uses Claude to reason and invoke tools for incident handling

Run:
    python langchain_agent/agent.py

Requires:
    ANTHROPIC_API_KEY in environment or .env file
"""

import asyncio
import os
import sys
from dotenv import load_dotenv

load_dotenv()

# ── LangChain + Anthropic ─────────────────────────────────────────────────────
try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_core.tools import StructuredTool
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
except ImportError:
    print("Installing LangChain dependencies...")
    os.system("pip install langchain langchain-anthropic langchain-core --break-system-packages -q")
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_core.tools import StructuredTool
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

# ── MCP Client ────────────────────────────────────────────────────────────────
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import json
from pydantic import BaseModel, create_model
from typing import Any, Optional

# ── MCP → LangChain Tool Bridge ───────────────────────────────────────────────

def mcp_schema_to_pydantic(schema: dict) -> type[BaseModel]:
    """Convert MCP JSON schema to a Pydantic model for LangChain."""
    fields = {}
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    
    type_map = {
        "string":  (str, ...),
        "integer": (int, ...),
        "boolean": (bool, ...),
        "array":   (list, ...),
    }
    
    for field_name, field_def in properties.items():
        py_type, _ = type_map.get(field_def.get("type", "string"), (str, ...))
        default = ... if field_name in required else field_def.get("default", None)
        if field_name not in required:
            py_type = Optional[py_type]
        fields[field_name] = (py_type, default)
    
    return create_model("DynamicInput", **fields)

async def build_langchain_tools(session: ClientSession) -> list[StructuredTool]:
    """Discover MCP tools and wrap them as LangChain StructuredTools."""
    result = await session.list_tools()
    tools = []
    
    for mcp_tool in result.tools:
        tool_name = mcp_tool.name
        tool_desc = mcp_tool.description
        input_schema = mcp_tool.inputSchema

        # Create Pydantic model for tool inputs
        ArgsModel = mcp_schema_to_pydantic(input_schema)

        # Create an async function that calls the MCP tool
        async def _call_tool(session=session, name=tool_name, **kwargs) -> str:
            # Remove None values
            clean_kwargs = {k: v for k, v in kwargs.items() if v is not None}
            result = await session.call_tool(name, arguments=clean_kwargs)
            return result.content[0].text if result.content else "No result"

        # Wrap as LangChain StructuredTool
        lc_tool = StructuredTool.from_function(
            coroutine=_call_tool,
            name=tool_name,
            description=tool_desc,
            args_schema=ArgsModel,
        )
        tools.append(lc_tool)
        print(f"  ✓ Loaded tool: {tool_name}")
    
    return tools

# ── Agent Setup ───────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are ARIA (Automated Response & Investigation Agent), a senior SOC analyst AI.

You have access to SIEM tools. When investigating security incidents:
1. Search for relevant log events
2. List and retrieve alerts  
3. Enrich suspicious IPs with threat intelligence
4. Create incidents to formally track confirmed threats

Always reason step by step. For each finding, explain what it means from a security perspective.
When creating incidents, include a clear description with your analysis.

Be concise but thorough. Format output clearly with sections."""

async def run_agent(query: str):
    """Main agent loop: connect to MCP server and run the agent."""
    
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("⚠️  ANTHROPIC_API_KEY not set. Using mock mode.\n")
        await mock_demo()
        return

    server_path = os.path.join(os.path.dirname(__file__), "../mcp_server/siem_server.py")
    
    server_params = StdioServerParameters(
        command="python",
        args=[server_path],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("✅ Connected to SIEM MCP Server\n")
            
            # Discover and wrap tools
            print("🔧 Loading SIEM tools...")
            tools = await build_langchain_tools(session)
            print(f"\n📡 {len(tools)} tools available\n")
            print("─" * 50)

            # LangChain agent
            llm = ChatAnthropic(model="claude-opus-4-5", api_key=api_key)

            prompt = ChatPromptTemplate.from_messages([
                ("system", SYSTEM_PROMPT),
                MessagesPlaceholder("chat_history", optional=True),
                ("human", "{input}"),
                MessagesPlaceholder("agent_scratchpad"),
            ])

            agent = create_tool_calling_agent(llm, tools, prompt)
            executor = AgentExecutor(agent=agent, tools=tools, verbose=True, max_iterations=8)

            print(f"🤖 ARIA: Processing request...\n")
            result = await executor.ainvoke({"input": query})
            print("\n" + "═" * 50)
            print("🤖 ARIA FINAL RESPONSE:")
            print("═" * 50)
            print(result["output"])

# ── Mock Demo (no API key needed) ────────────────────────────────────────────

async def mock_demo():
    """
    Demonstrate the MCP server tools directly without LangChain/API key.
    Shows exactly what the agent would receive from each tool.
    """
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    import os

    server_path = os.path.join(os.path.dirname(__file__), "../mcp_server/siem_server.py")
    server_params = StdioServerParameters(command="python", args=[server_path])

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("✅ Connected to SIEM MCP Server (Mock Mode)\n")

            steps = [
                ("list_alerts",   {"severity": "critical"},          "Step 1: List critical alerts"),
                ("get_alert",     {"alert_id": "ALT-104"},           "Step 2: Inspect data exfiltration alert"),
                ("enrich_ip",     {"ip_address": "198.51.100.5"},    "Step 3: Enrich suspicious external IP"),
                ("search_logs",   {"query": "admin"},                "Step 4: Search all events for 'admin' user"),
                ("create_incident", {
                    "title": "Critical: Data Exfiltration by admin account",
                    "alert_ids": ["ALT-101", "ALT-104"],
                    "severity": "critical",
                    "description": "Admin account shows brute-force attack followed by data exfiltration to known C2 server (198.51.100.5). Likely compromised account.",
                    "assignee": "soc_analyst_1"
                }, "Step 5: Create incident"),
            ]

            for tool_name, args, label in steps:
                print(f"\n{'─'*50}")
                print(f"🔧 {label}")
                print(f"   Tool: {tool_name}({json.dumps(args, indent=6)})")
                result = await session.call_tool(tool_name, arguments=args)
                data = json.loads(result.content[0].text)
                print(f"   Result: {json.dumps(data, indent=6)}")

            print(f"\n{'═'*50}")
            print("✅ Mock demo complete. All 5 SIEM tools demonstrated.")
            print("\nNext step: Set ANTHROPIC_API_KEY to run the full LangChain agent.")

# ── CLI Entry ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else \
        "Investigate all critical alerts. Enrich any suspicious IPs and create an incident if warranted."
    
    print("╔══════════════════════════════════════════╗")
    print("║  ARIA - SIEM Incident Handling Agent      ║")
    print("║  Powered by MCP + LangChain + Claude      ║")
    print("╚══════════════════════════════════════════╝\n")
    print(f"📋 Query: {query}\n")
    
    asyncio.run(run_agent(query))
