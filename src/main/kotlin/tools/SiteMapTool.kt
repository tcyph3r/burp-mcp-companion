package tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.sitemap.SiteMapFilter
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.serialization.json.*
import security.ApprovalManager
import security.AuditLogger
import security.OutputSanitizer

/**
 * MCP Tool: get_sitemap
 */
object SiteMapTool {

    private const val MAX_ENTRIES = 1000

    fun register(server: Server, api: MontoyaApi, approvalManager: ApprovalManager, auditLogger: AuditLogger) {
        val toolName = "get_sitemap"
        server.addTool(
            tool = Tool(
                name = toolName,
                description = "Returns the Burp Suite site map. Optionally filter by URL prefix (e.g. 'https://example.com'). " +
                    "Returns list of {method, url, statusCode, mimeType, length}. Max $MAX_ENTRIES entries.",
                inputSchema = ToolSchema(
                    properties = buildJsonObject {
                        putJsonObject("host") {
                            put("type", "string")
                            put("description", "Optional URL prefix filter (e.g. 'https://example.com')")
                        }
                    },
                    required = emptyList()
                )
            )
        ) { request ->
            try {
                val prefix = request.params.arguments?.get("host")?.jsonPrimitive?.contentOrNull
                val target = prefix ?: "entire site map"

                if (!approvalManager.requestApproval(ApprovalManager.ApprovalLevel.DATA_ACCESS, toolName, target)) {
                    auditLogger.log(toolName, target, false, AuditLogger.Result.DENIED)
                    return@addTool CallToolResult(
                        content = listOf(TextContent("Access denied: User did not approve data access for '$target'.")),
                        isError = true
                    )
                }

                // SiteMapFilter.prefixFilter(String) is the confirmed API
                val entries = if (prefix != null) {
                    api.siteMap().requestResponses(SiteMapFilter.prefixFilter(prefix))
                } else {
                    api.siteMap().requestResponses().filter { reqResp ->
                        val url = reqResp.request()?.url()
                        url != null && api.scope().isInScope(url)
                    }
                }

                val results = entries.take(MAX_ENTRIES).mapNotNull { reqResp ->
                    try {
                        val req = reqResp.request() ?: return@mapNotNull null
                        val resp = reqResp.response()
                        buildJsonObject {
                            put("method", req.method())
                            put("url", OutputSanitizer.sanitize(req.url()))
                            put("statusCode", resp?.statusCode() ?: 0)
                            put("mimeType", OutputSanitizer.sanitize(resp?.statedMimeType()?.toString() ?: "unknown"))
                            put("length", resp?.body()?.length() ?: 0)
                        }
                    } catch (e: Exception) { null }
                }

                val resultJson = buildJsonObject {
                    put("count", results.size)
                    put("truncated", entries.size > MAX_ENTRIES)
                    put("entries", JsonArray(results))
                }

                auditLogger.log(toolName, target, true, AuditLogger.Result.SUCCESS)
                CallToolResult(content = listOf(TextContent(OutputSanitizer.sanitize(resultJson.toString()))))
            } catch (e: Exception) {
                auditLogger.log(toolName, "unknown", null, AuditLogger.Result.ERROR)
                CallToolResult(content = listOf(TextContent("Error: ${e.message}")), isError = true)
            }
        }
    }
}
