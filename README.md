# Burp MCP Companion

A Burp Suite extension that exposes a **Model Context Protocol (MCP) server** over SSE, giving AI assistants like Claude direct, structured access to Burp's scanner, sitemap, scope management, cookies, and request annotations.

Built security-first: every tool call goes through host allowlisting, rate limiting, optional per-action approval, and audit logging — so an AI agent can drive Burp without needing unsupervised access.

## What it does

The extension starts an SSE server on **port 9877** and exposes 9 MCP tools:

| Tool | Description |
|------|-------------|
| `get_sitemap` | Retrieve site map entries, with optional host/path filter |
| `get_scope` | List all in-scope targets |
| `add_to_scope` | Add a URL to Burp's scope |
| `remove_from_scope` | Remove a URL from Burp's scope |
| `get_scan_status` | Get active scanner issues, filtered to in-scope targets |
| `start_crawl_and_scan` | Launch a crawl + audit scan against a URL |
| `get_cookies` | Retrieve cookies from Burp's cookie jar |
| `add_comment` | Annotate a proxy history entry with a comment |
| `highlight_request` | Highlight a proxy history entry by colour |

## Security controls

- **Host allowlist** — tools only operate on hosts you've explicitly approved
- **Rate limiter** — prevents AI agents from flooding Burp with requests
- **Approval manager** — optional human-in-the-loop confirmation for destructive actions
- **Audit logger** — full log of every tool call with timestamp and parameters
- **Output sanitizer** — strips sensitive data from tool responses before returning to the AI

## Usage

### 1. Build

```bash
# Windows
gradlew jar

# Unix
./gradlew jar
```

The JAR is output to `build/libs/`.

### 2. Load in Burp

1. **Extensions > Installed > Add**
2. Select the JAR file
3. Click **Next** — the extension loads and starts the MCP server on port 9877

### 3. Connect Claude Code

Add to your Claude Code MCP config (`.mcp.json` or `~/.claude.json`):

```json
{
  "mcpServers": {
    "burp-mcp-companion": {
      "type": "sse",
      "url": "http://127.0.0.1:9877/sse"
    }
  }
}
```

### 4. Use alongside the official Burp MCP proxy

This extension complements (not replaces) the [official Burp MCP proxy](https://portswigger.net/burp/documentation/desktop/tools/mcp-integration). Run both simultaneously:

- **Companion** (port 9877) — scope-aware scanner, sitemap, annotations, cookies
- **Official proxy** (port 9876) — raw proxy history, Repeater, Intruder, Collaborator, encoding tools

## Requirements

- Burp Suite Pro (2024.x or later)
- JDK 21+
- Montoya API 2025.10 (bundled via Gradle)

## Tech stack

- **Kotlin** — extension source
- **Burp Montoya API** — Burp integration layer
- **MCP over SSE** — AI assistant protocol transport
- **Gradle (Kotlin DSL)** — build system

## Project structure

```
src/main/kotlin/
├── Extension.kt               # Entry point
├── server/
│   ├── McpServerManager.kt    # SSE server + MCP protocol handling
│   └── TaskRegistry.kt        # Tool registration
├── tools/
│   ├── SiteMapTool.kt
│   ├── ScopeTools.kt
│   ├── ScannerTools.kt
│   ├── CookieTool.kt
│   ├── AnnotationTools.kt
│   └── WebSocketTool.kt
├── security/
│   ├── AllowlistManager.kt
│   ├── ApprovalManager.kt
│   ├── AuditLogger.kt
│   ├── OutputSanitizer.kt
│   ├── RateLimiter.kt
│   └── ScopeChecker.kt
└── ui/
    └── CompanionTab.kt        # Burp UI tab
```
