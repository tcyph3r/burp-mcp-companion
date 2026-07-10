package tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.CrawlConfiguration
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.serialization.json.*
import security.ApprovalManager
import security.AuditLogger
import security.RateLimiter
import security.ScopeChecker
import server.TaskRegistry
import java.util.UUID

/**
 * MCP Tools: start_crawl_and_scan, get_scan_status
 * 
 * Scanner issues are retrieved via api.siteMap().issues() (confirmed from Montoya 2026.4 API).
 * api.scanner() has no issues() method — only startCrawl/startAudit/registerChecks.
 */
object ScannerTools {

    fun register(
        server: Server, api: MontoyaApi, approvalManager: ApprovalManager,
        scopeChecker: ScopeChecker, rateLimiter: RateLimiter,
        auditLogger: AuditLogger, taskRegistry: TaskRegistry
    ) {
        registerStartCrawlAndScan(server, api, approvalManager, scopeChecker, rateLimiter, auditLogger, taskRegistry)
        registerGetScanStatus(server, api, auditLogger, taskRegistry)
    }

    private fun registerStartCrawlAndScan(
        server: Server, api: MontoyaApi, approvalManager: ApprovalManager,
        scopeChecker: ScopeChecker, rateLimiter: RateLimiter,
        auditLogger: AuditLogger, taskRegistry: TaskRegistry
    ) {
        val toolName = "start_crawl_and_scan"
        server.addTool(
            tool = Tool(
                name = toolName,
                description = "Starts a crawl on the target URL. Burp's passive scanner will automatically " +
                    "analyze discovered content. The URL MUST be in Burp's target scope. " +
                    "Requires explicit user approval and is rate-limited (2/min per host).",
                inputSchema = ToolSchema(
                    properties = buildJsonObject {
                        putJsonObject("url") {
                            put("type", "string")
                            put("description", "Target URL to crawl (must be in Burp scope)")
                        }
                    },
                    required = listOf("url")
                )
            )
        ) { request ->
            try {
                val url = request.params.arguments?.get("url")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(listOf(TextContent("Error: 'url' parameter is required.")), true)

                val host = scopeChecker.extractHost(url) ?: "unknown"

                val rateLimitError = rateLimiter.tryAcquire(host, category = "scan")
                if (rateLimitError != null) {
                    auditLogger.log(toolName, url, false, AuditLogger.Result.DENIED)
                    return@addTool CallToolResult(listOf(TextContent(rateLimitError)), true)
                }

                if (!scopeChecker.isInScope(url)) {
                    auditLogger.log(toolName, url, false, AuditLogger.Result.DENIED)
                    return@addTool CallToolResult(listOf(TextContent("DENIED: Target not in scope. Add it first using 'add_to_scope'.")), true)
                }

                if (!approvalManager.requestApproval(ApprovalManager.ApprovalLevel.EXPLICIT_APPROVAL, toolName, url)) {
                    auditLogger.log(toolName, url, false, AuditLogger.Result.DENIED)
                    return@addTool CallToolResult(listOf(TextContent("DENIED: User did not approve the scan on '$url'.")), true)
                }

                val crawlConfig = CrawlConfiguration.crawlConfiguration(url)
                val crawl = api.scanner().startCrawl(crawlConfig)

                val taskId = UUID.randomUUID().toString()
                taskRegistry.register(taskId, crawl, url)

                auditLogger.log(toolName, url, true, AuditLogger.Result.SUCCESS)
                CallToolResult(listOf(TextContent("Crawl started on: $url\nTask ID: $taskId\nUse 'get_scan_status' to check progress.")))
            } catch (e: Exception) {
                auditLogger.log(toolName, "unknown", null, AuditLogger.Result.ERROR)
                CallToolResult(listOf(TextContent("Error starting crawl: ${e.message}")), true)
            }
        }
    }

    private fun registerGetScanStatus(server: Server, api: MontoyaApi, auditLogger: AuditLogger, taskRegistry: TaskRegistry) {
        val toolName = "get_scan_status"
        server.addTool(
            tool = Tool(
                name = toolName,
                description = "Returns information about active scan tasks and scanner issues found in the site map. " +
                    "Issues are automatically filtered to the current Burp scope.",
                inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
            )
        ) { _ ->
            try {
                val activeTasks = taskRegistry.getAllTasks().map { (id, info) ->
                    buildJsonObject {
                        put("taskId", id)
                        put("targetUrl", info.targetUrl)
                        put("durationMs", System.currentTimeMillis() - info.startTimeMs)
                    }
                }

                // Confirmed API: scanner issues are on api.siteMap().issues(), not api.scanner()
                val issues = api.siteMap().issues().filter { issue ->
                    api.scope().isInScope(issue.baseUrl())
                }
                val recentIssues = issues.takeLast(10).map { issue ->
                    buildJsonObject {
                        put("name", issue.name())
                        put("severity", issue.severity().name)
                        put("confidence", issue.confidence().name)
                        put("url", issue.baseUrl())
                    }
                }

                val statusJson = buildJsonObject {
                    put("activeTasks", JsonArray(activeTasks))
                    put("totalIssuesFound", issues.size)
                    put("recentIssues", JsonArray(recentIssues))
                }

                auditLogger.log(toolName, "none", null, AuditLogger.Result.SUCCESS)
                CallToolResult(listOf(TextContent(statusJson.toString())))
            } catch (e: Exception) {
                auditLogger.log(toolName, "none", null, AuditLogger.Result.ERROR)
                CallToolResult(listOf(TextContent("Error getting scan status: ${e.message}")), true)
            }
        }
    }
}
