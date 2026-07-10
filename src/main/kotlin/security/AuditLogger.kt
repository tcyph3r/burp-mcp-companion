package security

import burp.api.montoya.MontoyaApi
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Audit logger for MCP tool calls.
 *
 * Logs a single structured line per tool invocation to Burp's output:
 *   [MCP] 2026-07-07T12:34:56Z tool=get_sitemap target=example.com approved=true result=SUCCESS
 *
 * Does NOT log request/response bodies — only metadata.
 */
class AuditLogger(private val api: MontoyaApi) {

    companion object {
        private val TIMESTAMP_FORMAT = DateTimeFormatter.ISO_INSTANT
    }

    enum class Result {
        SUCCESS, DENIED, ERROR
    }

    /**
     * Logs a tool call with its outcome.
     *
     * @param toolName MCP tool name
     * @param target Target host/URL, or "none" for tools with no target
     * @param approved true/false/null (null = not applicable, e.g. no approval needed)
     * @param result SUCCESS, DENIED, or ERROR
     */
    fun log(toolName: String, target: String = "none", approved: Boolean? = null, result: Result) {
        val timestamp = Instant.now().toString()
        val approvedStr = when (approved) {
            true -> "true"
            false -> "false"
            null -> "na"
        }

        val logLine = "[MCP] $timestamp tool=$toolName target=$target approved=$approvedStr result=${result.name}"
        api.logging().logToOutput(logLine)
    }
}
