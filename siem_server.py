"""
SIEM MCP Server
===============
Exposes SIEM capabilities as MCP tools that any AI agent (LangChain, Claude, etc.) can call.

Tools exposed:
  - search_logs      : Search SIEM events by keyword/query
  - get_alert        : Fetch a specific alert by ID
  - list_alerts      : List recent alerts by severity
  - enrich_ip        : Threat intel lookup for an IP address
  - create_incident  : Create an incident ticket from an alert
"""

import asyncio
import json
import random
from datetime import datetime, timedelta
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# ── Simulated SIEM Data ───────────────────────────────────────────────────────

MOCK_EVENTS = [
    {"id": "EVT-001", "timestamp": "2026-05-05T08:12:00Z", "source_ip": "185.220.101.45", "dest_ip": "10.0.1.15", "event_type": "brute_force", "severity": "high", "message": "Multiple failed SSH login attempts from external IP", "user": "admin", "count": 47},
    {"id": "EVT-002", "timestamp": "2026-05-05T08:45:00Z", "source_ip": "10.0.1.88",     "dest_ip": "10.0.2.5",  "event_type": "lateral_movement", "severity": "critical", "message": "Unusual SMB traffic detected between internal hosts", "user": "svc_backup", "count": 12},
    {"id": "EVT-003", "timestamp": "2026-05-05T09:01:00Z", "source_ip": "203.0.113.77",  "dest_ip": "10.0.1.22", "event_type": "phishing_click", "severity": "medium", "message": "User clicked suspicious link in email", "user": "j.smith", "count": 1},
    {"id": "EVT-004", "timestamp": "2026-05-05T09:30:00Z", "source_ip": "10.0.1.15",     "dest_ip": "198.51.100.5", "event_type": "data_exfiltration", "severity": "critical", "message": "Large data transfer to unknown external IP", "user": "admin", "count": 1},
    {"id": "EVT-005", "timestamp": "2026-05-05T10:00:00Z", "source_ip": "10.0.1.5",      "dest_ip": "10.0.1.200", "event_type": "privilege_escalation", "severity": "high", "message": "Unexpected sudo command executed by non-privileged user", "user": "m.jones", "count": 3},
]

MOCK_ALERTS = [
    {"alert_id": "ALT-101", "title": "Brute Force Attack Detected",        "severity": "high",     "status": "open",         "event_ids": ["EVT-001"], "created": "2026-05-05T08:15:00Z", "assignee": None},
    {"alert_id": "ALT-102", "title": "Lateral Movement - Internal SMB",    "severity": "critical", "status": "investigating","event_ids": ["EVT-002"], "created": "2026-05-05T08:47:00Z", "assignee": "soc_analyst_1"},
    {"alert_id": "ALT-103", "title": "Phishing Click by j.smith",          "severity": "medium",   "status": "open",         "event_ids": ["EVT-003"], "created": "2026-05-05T09:05:00Z", "assignee": None},
    {"alert_id": "ALT-104", "title": "Suspected Data Exfiltration",        "severity": "critical", "status": "open",         "event_ids": ["EVT-004"], "created": "2026-05-05T09:32:00Z", "assignee": None},
    {"alert_id": "ALT-105", "title": "Privilege Escalation - m.jones",     "severity": "high",     "status": "open",         "event_ids": ["EVT-005"], "created": "2026-05-05T10:02:00Z", "assignee": None},
]

THREAT_INTEL = {
    "185.220.101.45": {"reputation": "malicious", "country": "RU", "asn": "AS209605", "tags": ["tor-exit-node", "brute-force"], "confidence": 95},
    "203.0.113.77":   {"reputation": "suspicious","country": "CN", "asn": "AS4134",   "tags": ["phishing-host"],                "confidence": 72},
    "198.51.100.5":   {"reputation": "malicious", "country": "NL", "asn": "AS60781",  "tags": ["c2-server", "data-sink"],       "confidence": 88},
}

INCIDENTS = []  # Will accumulate created incidents

# ── MCP Server Setup ──────────────────────────────────────────────────────────

app = Server("siem-mcp-server")

# ── Tool: search_logs ─────────────────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="search_logs",
            description="Search SIEM event logs using a keyword or field filter (e.g. event type, user, IP). Returns matching log events.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query":    {"type": "string", "description": "Search keyword - e.g. 'brute_force', 'admin', '10.0.1.15'"},
                    "severity": {"type": "string", "enum": ["low","medium","high","critical","all"], "description": "Filter by severity level"},
                    "limit":    {"type": "integer", "description": "Max results to return (default 10)", "default": 10},
                },
                "required": ["query"],
            },
        ),
        types.Tool(
            name="get_alert",
            description="Retrieve a specific SIEM alert and its associated events by Alert ID (e.g. ALT-101).",
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string", "description": "Alert ID like ALT-101"},
                },
                "required": ["alert_id"],
            },
        ),
        types.Tool(
            name="list_alerts",
            description="List recent SIEM alerts, optionally filtered by severity or status.",
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["medium","high","critical","all"], "default": "all"},
                    "status":   {"type": "string", "enum": ["open","investigating","closed","all"], "default": "all"},
                },
            },
        ),
        types.Tool(
            name="enrich_ip",
            description="Look up threat intelligence for a given IP address. Returns reputation, country, ASN, and tags.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "IP address to enrich, e.g. 185.220.101.45"},
                },
                "required": ["ip_address"],
            },
        ),
        types.Tool(
            name="create_incident",
            description="Create a formal incident from one or more SIEM alerts. Returns an incident ID for tracking.",
            inputSchema={
                "type": "object",
                "properties": {
                    "title":       {"type": "string", "description": "Incident title"},
                    "alert_ids":   {"type": "array", "items": {"type": "string"}, "description": "Alert IDs to link"},
                    "severity":    {"type": "string", "enum": ["low","medium","high","critical"]},
                    "description": {"type": "string", "description": "Summary of the incident"},
                    "assignee":    {"type": "string", "description": "Analyst to assign (optional)"},
                },
                "required": ["title", "alert_ids", "severity", "description"],
            },
        ),
    ]

# ── Tool Handlers ─────────────────────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:

    if name == "search_logs":
        query = arguments["query"].lower()
        sev_filter = arguments.get("severity", "all")
        limit = arguments.get("limit", 10)

        results = [
            e for e in MOCK_EVENTS
            if query in e["message"].lower()
            or query in e["source_ip"]
            or query in e["dest_ip"]
            or query in e["event_type"]
            or query in e.get("user", "")
        ]
        if sev_filter != "all":
            results = [e for e in results if e["severity"] == sev_filter]

        results = results[:limit]
        output = {
            "total_found": len(results),
            "query": query,
            "events": results,
        }
        return [types.TextContent(type="text", text=json.dumps(output, indent=2))]

    elif name == "get_alert":
        alert_id = arguments["alert_id"].upper()
        alert = next((a for a in MOCK_ALERTS if a["alert_id"] == alert_id), None)
        if not alert:
            return [types.TextContent(type="text", text=json.dumps({"error": f"Alert {alert_id} not found"}))]

        # Attach linked events
        linked_events = [e for e in MOCK_EVENTS if e["id"] in alert["event_ids"]]
        result = {**alert, "events": linked_events}
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "list_alerts":
        sev_filter    = arguments.get("severity", "all")
        status_filter = arguments.get("status", "all")
        results = MOCK_ALERTS
        if sev_filter != "all":
            results = [a for a in results if a["severity"] == sev_filter]
        if status_filter != "all":
            results = [a for a in results if a["status"] == status_filter]
        return [types.TextContent(type="text", text=json.dumps({"total": len(results), "alerts": results}, indent=2))]

    elif name == "enrich_ip":
        ip = arguments["ip_address"]
        intel = THREAT_INTEL.get(ip, {"reputation": "unknown", "country": "N/A", "asn": "N/A", "tags": [], "confidence": 0})
        result = {"ip": ip, **intel}
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "create_incident":
        incident_id = f"INC-{1000 + len(INCIDENTS) + 1}"
        incident = {
            "incident_id": incident_id,
            "title":       arguments["title"],
            "alert_ids":   arguments["alert_ids"],
            "severity":    arguments["severity"],
            "description": arguments["description"],
            "assignee":    arguments.get("assignee", "unassigned"),
            "status":      "open",
            "created":     datetime.utcnow().isoformat() + "Z",
        }
        INCIDENTS.append(incident)
        return [types.TextContent(type="text", text=json.dumps(incident, indent=2))]

    else:
        return [types.TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

# ── Entry Point ───────────────────────────────────────────────────────────────

async def main():
    print("[SIEM MCP Server] Starting over stdio...", flush=True)
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
