package tools

import io.modelcontextprotocol.kotlin.sdk.server.Server

/**
 * STUB: send_websocket_message
 * 
 * Tool removed per design review (Fix 3).
 * 
 * Reason: 
 * The Montoya API (api.proxy().webSocketHistory()) provides access to completed
 * WebSocket sessions for inspection, but there is currently no API surface for 
 * injecting messages into LIVE WebSocket connections. 
 * 
 * We do not expose a tool that would silently fail or mislead the agent.
 * This file is kept as a placeholder in case the Montoya API gains live WS
 * injection capabilities in a future release (e.g. 2026.x+).
 */
object WebSocketTool {

    fun register(server: Server) {
        // No-op
    }
}
