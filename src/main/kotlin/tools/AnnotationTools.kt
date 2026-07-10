package tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.HighlightColor
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.serialization.json.*
import security.AuditLogger
import security.OutputSanitizer

/**
 * MCP Tools: highlight_request, add_comment
 */
object AnnotationTools {

    private val COLOR_MAP = mapOf(
        "RED" to HighlightColor.RED, "ORANGE" to HighlightColor.ORANGE,
        "YELLOW" to HighlightColor.YELLOW, "GREEN" to HighlightColor.GREEN,
        "CYAN" to HighlightColor.CYAN, "BLUE" to HighlightColor.BLUE,
        "PINK" to HighlightColor.PINK, "MAGENTA" to HighlightColor.MAGENTA,
        "GRAY" to HighlightColor.GRAY, "NONE" to HighlightColor.NONE,
    )

    fun register(server: Server, api: MontoyaApi, auditLogger: AuditLogger) {
        registerHighlightRequest(server, api, auditLogger)
        registerAddComment(server, api, auditLogger)
    }

    private fun registerHighlightRequest(server: Server, api: MontoyaApi, auditLogger: AuditLogger) {
        val toolName = "highlight_request"
        server.addTool(
            tool = Tool(
                name = toolName,
                description = "Sets the highlight color of a proxy history entry. " +
                    "Colors: RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY, NONE. " +
                    "requestIndex is 0-based index into proxy history.",
                inputSchema = ToolSchema(
                    properties = buildJsonObject {
                        putJsonObject("requestIndex") { put("type", "integer") }
                        putJsonObject("color") {
                            put("type", "string")
                            put("enum", buildJsonArray { COLOR_MAP.keys.forEach { add(it) } })
                        }
                    },
                    required = listOf("requestIndex", "color")
                )
            )
        ) { request ->
            try {
                val index = request.params.arguments?.get("requestIndex")?.jsonPrimitive?.intOrNull
                    ?: return@addTool CallToolResult(listOf(TextContent("Error: 'requestIndex' required.")), true)
                val colorName = request.params.arguments?.get("color")?.jsonPrimitive?.contentOrNull?.uppercase()
                    ?: return@addTool CallToolResult(listOf(TextContent("Error: 'color' required.")), true)
                val highlightColor = COLOR_MAP[colorName]
                    ?: return@addTool CallToolResult(listOf(TextContent("Error: Invalid color '$colorName'.")), true)

                val history = api.proxy().history()
                if (index < 0 || index >= history.size) {
                    return@addTool CallToolResult(listOf(TextContent("Error: Index $index out of bounds (history size: ${history.size}).")), true)
                }

                history[index].annotations().setHighlightColor(highlightColor)
                auditLogger.log(toolName, "history[$index]", null, AuditLogger.Result.SUCCESS)
                CallToolResult(listOf(TextContent("Entry #$index highlighted $colorName.")))
            } catch (e: Exception) {
                auditLogger.log(toolName, "unknown", null, AuditLogger.Result.ERROR)
                CallToolResult(listOf(TextContent("Error: ${e.message}")), true)
            }
        }
    }

    private fun registerAddComment(server: Server, api: MontoyaApi, auditLogger: AuditLogger) {
        val toolName = "add_comment"
        server.addTool(
            tool = Tool(
                name = toolName,
                description = "Adds a comment to a proxy history entry. Max 500 characters.",
                inputSchema = ToolSchema(
                    properties = buildJsonObject {
                        putJsonObject("requestIndex") { put("type", "integer") }
                        putJsonObject("comment") { put("type", "string") }
                    },
                    required = listOf("requestIndex", "comment")
                )
            )
        ) { request ->
            try {
                val index = request.params.arguments?.get("requestIndex")?.jsonPrimitive?.intOrNull
                    ?: return@addTool CallToolResult(listOf(TextContent("Error: 'requestIndex' required.")), true)
                val rawComment = request.params.arguments?.get("comment")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(listOf(TextContent("Error: 'comment' required.")), true)

                val history = api.proxy().history()
                if (index < 0 || index >= history.size) {
                    return@addTool CallToolResult(listOf(TextContent("Error: Index $index out of bounds.")), true)
                }

                val sanitized = OutputSanitizer.sanitizeComment(rawComment)
                history[index].annotations().setNotes(sanitized)

                auditLogger.log(toolName, "history[$index]", null, AuditLogger.Result.SUCCESS)
                CallToolResult(listOf(TextContent("Comment added to entry #$index.")))
            } catch (e: Exception) {
                auditLogger.log(toolName, "unknown", null, AuditLogger.Result.ERROR)
                CallToolResult(listOf(TextContent("Error: ${e.message}")), true)
            }
        }
    }
}
