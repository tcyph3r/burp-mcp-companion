package tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.Cookie
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.serialization.json.*
import security.ApprovalManager
import security.AuditLogger
import security.OutputSanitizer

/**
 * MCP Tool: get_cookies
 *
 * Confirmed Montoya 2026.4 CookieJar API:
 *   api.http().cookieJar().cookies() → List<Cookie>
 *   No cookiesForDomain() method — we filter in-memory.
 *
 * BUG FIX: We now fetch and filter cookies BEFORE requesting approval.
 * If no cookies match the domain we return [] immediately without a dialog.
 * This prevents the approval dialog timing out for domains with no cookies.
 */
object CookieTool {

    fun register(server: Server, api: MontoyaApi, approvalManager: ApprovalManager, auditLogger: AuditLogger) {
        val toolName = "get_cookies"
        server.addTool(
            tool = Tool(
                name = toolName,
                description = "Returns cookie metadata (name, domain, path, expiry) for a given domain. " +
                    "Cookie VALUES are NOT returned for security reasons. Returns [] if no cookies exist for the domain.",
                inputSchema = ToolSchema(
                    properties = buildJsonObject {
                        putJsonObject("domain") {
                            put("type", "string")
                            put("description", "Domain to filter cookies by (e.g. 'example.com')")
                        }
                    },
                    required = listOf("domain")
                )
            )
        ) { request ->
            try {
                val domain = request.params.arguments?.get("domain")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(listOf(TextContent("Error: 'domain' required.")), true)

                // Fetch and filter BEFORE showing any approval dialog.
                // If no cookies match, return [] immediately — no point asking for approval.
                val allCookies: List<Cookie> = api.http().cookieJar().cookies()
                val filtered = allCookies.filter { cookie ->
                    cookie.domain().equals(domain, ignoreCase = true) ||
                        cookie.domain().endsWith(".$domain", ignoreCase = true)
                }

                if (filtered.isEmpty()) {
                    auditLogger.log(toolName, domain, null, AuditLogger.Result.SUCCESS)
                    return@addTool CallToolResult(listOf(TextContent(
                        buildJsonObject {
                            put("domain", domain)
                            put("count", 0)
                            put("cookies", JsonArray(emptyList()))
                            put("note", "No cookies found for this domain.")
                        }.toString()
                    )))
                }

                // Only ask for approval if there is actually something to share
                if (!approvalManager.requestApproval(ApprovalManager.ApprovalLevel.DATA_ACCESS, toolName, domain)) {
                    auditLogger.log(toolName, domain, false, AuditLogger.Result.DENIED)
                    return@addTool CallToolResult(listOf(TextContent("DENIED: Data access not approved.")), true)
                }

                val cookieList = filtered.map { cookie ->
                    buildJsonObject {
                        put("name", OutputSanitizer.sanitize(cookie.name()))
                        put("domain", OutputSanitizer.sanitize(cookie.domain()))
                        put("path", OutputSanitizer.sanitize(cookie.path()))
                        put("expiry", cookie.expiration()?.toString() ?: "session")
                        // Security: value intentionally omitted
                    }
                }

                val resultJson = buildJsonObject {
                    put("domain", domain)
                    put("count", cookieList.size)
                    put("cookies", JsonArray(cookieList))
                    put("note", "Values omitted for security.")
                }

                auditLogger.log(toolName, domain, true, AuditLogger.Result.SUCCESS)
                CallToolResult(listOf(TextContent(OutputSanitizer.sanitize(resultJson.toString()))))
            } catch (e: Exception) {
                auditLogger.log(toolName, "unknown", null, AuditLogger.Result.ERROR)
                CallToolResult(listOf(TextContent("Error: ${e.message}")), true)
            }
        }
    }
}
