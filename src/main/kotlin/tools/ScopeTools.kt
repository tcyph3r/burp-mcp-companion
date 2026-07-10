package tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.sitemap.SiteMapFilter
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.serialization.json.*
import security.ApprovalManager
import security.AuditLogger
import security.OutputSanitizer
import java.net.URI

/**
 * MCP Tools: get_scope, add_to_scope, remove_from_scope
 *
 * NOTE on add_to_scope + includeSubdomains:
 * Montoya's includeInScope(url) only adds a simple prefix rule.
 * When includeSubdomains=true, we inject a rule via project options JSON
 * using the host regex pattern "(.*\\.)?<domain>" so Burp matches all subdomains.
 *
 * NOTE on remove_from_scope:
 * Montoya has no removeFromScope() / removeIncludeRule() method.
 * The only way to delete an include rule is via project options JSON.
 * We export → parse → filter matching prefix → reimport.
 * Only target.scope.include is modified — exclude and all other settings are untouched.
 */
object ScopeTools {

    fun register(server: Server, api: MontoyaApi, approvalManager: ApprovalManager, auditLogger: AuditLogger) {
        registerGetScope(server, api, auditLogger)
        registerAddToScope(server, api, approvalManager, auditLogger)
        registerRemoveFromScope(server, api, approvalManager, auditLogger)
    }

    // ── get_scope ─────────────────────────────────────────────────────────────

    private fun registerGetScope(server: Server, api: MontoyaApi, auditLogger: AuditLogger) {
        val toolName = "get_scope"
        server.addTool(
            tool = Tool(
                name = toolName,
                description = "Returns the current Burp target scope rules in JSON format.",
                inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
            )
        ) { _ ->
            try {
                val scopeJson = api.burpSuite().exportProjectOptionsAsJson("target.scope")
                val scopeObj = Json.parseToJsonElement(scopeJson)
                auditLogger.log(toolName, "none", null, AuditLogger.Result.SUCCESS)
                val prettyJson = Json { prettyPrint = true }
                CallToolResult(listOf(TextContent(OutputSanitizer.sanitize(
                    prettyJson.encodeToString(JsonElement.serializer(), scopeObj)
                ))))
            } catch (e: Exception) {
                auditLogger.log(toolName, "none", null, AuditLogger.Result.ERROR)
                CallToolResult(listOf(TextContent("Error retrieving scope: ${e.message}")), true)
            }
        }
    }

    // ── add_to_scope ──────────────────────────────────────────────────────────

    private fun registerAddToScope(server: Server, api: MontoyaApi, approvalManager: ApprovalManager, auditLogger: AuditLogger) {
        val toolName = "add_to_scope"
        server.addTool(
            tool = Tool(
                name = toolName,
                description = "Adds a URL to Burp's target scope include list. " +
                    "Set includeSubdomains=true to also match all subdomains (e.g. sub.example.com). " +
                    "Requires explicit user approval.",
                inputSchema = ToolSchema(
                    properties = buildJsonObject {
                        putJsonObject("url") {
                            put("type", "string")
                            put("description", "URL to add to scope (e.g. https://example.com)")
                        }
                        putJsonObject("includeSubdomains") {
                            put("type", "boolean")
                            put("description", "If true, also matches all subdomains of the target host")
                        }
                    },
                    required = listOf("url")
                )
            )
        ) { request ->
            try {
                val url = request.params.arguments?.get("url")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(listOf(TextContent("Error: 'url' required.")), true)
                val includeSubdomains = request.params.arguments?.get("includeSubdomains")?.jsonPrimitive?.booleanOrNull ?: false

                val parsed = try { URI(url) } catch (e: Exception) {
                    return@addTool CallToolResult(listOf(TextContent("Error: Invalid URL: ${e.message}")), true)
                }
                val scheme = parsed.scheme?.lowercase()
                if (scheme != "http" && scheme != "https") {
                    return@addTool CallToolResult(listOf(TextContent("Error: URL must be http or https.")), true)
                }

                val description = if (includeSubdomains) "$url (+ subdomains)" else url
                if (!approvalManager.requestApproval(ApprovalManager.ApprovalLevel.EXPLICIT_APPROVAL, toolName, description)) {
                    auditLogger.log(toolName, url, false, AuditLogger.Result.DENIED)
                    return@addTool CallToolResult(listOf(TextContent("DENIED: User did not approve scope change.")), true)
                }

                if (!includeSubdomains) {
                    // Simple case: use the Montoya API directly
                    api.scope().includeInScope(url)
                    auditLogger.log(toolName, url, true, AuditLogger.Result.SUCCESS)
                    return@addTool CallToolResult(listOf(TextContent("Added to scope: $url")))
                }

                // Subdomain case: inject a rule via project options JSON
                val host = parsed.host ?: return@addTool CallToolResult(listOf(TextContent("Error: Cannot extract host from URL.")), true)
                val port = if (parsed.port > 0) parsed.port.toString() else ""
                val result = addSubdomainRule(api, scheme!!, host, port)

                auditLogger.log(toolName, url, result.second, AuditLogger.Result.SUCCESS)
                CallToolResult(listOf(TextContent(result.first)))
            } catch (e: Exception) {
                auditLogger.log(toolName, "unknown", null, AuditLogger.Result.ERROR)
                CallToolResult(listOf(TextContent("Error: ${e.message}")), true)
            }
        }
    }

    /**
     * Injects a scope include rule that matches both the base domain and all subdomains.
     * Uses host regex "(.*\.)?<escapedHost>" which is what Burp's UI generates when
     * "Include subdomains" is ticked in advanced scope control.
     */
    private fun addSubdomainRule(api: MontoyaApi, protocol: String, host: String, port: String): Pair<String, Boolean> {
        val exported = api.burpSuite().exportProjectOptionsAsJson("target.scope")
        val root = try { Json.parseToJsonElement(exported).jsonObject }
        catch (e: Exception) { return Pair("Error parsing scope JSON: ${e.message}", false) }

        val target = root["target"]?.jsonObject
            ?: return Pair("Error: no 'target' key in scope JSON.", false)
        val scope = target["scope"]?.jsonObject
            ?: return Pair("Error: no 'target.scope' key.", false)
        val includeArray = scope["include"]?.jsonArray ?: JsonArray(emptyList())

        // Escape the host for use as a regex (dots become \.)
        val escapedHost = host.replace(".", "\\.")
        val hostPattern = "(.*\\.)?$escapedHost"

        // Build the new rule in Burp's advanced scope format
        val newRule = buildJsonObject {
            put("enabled", true)
            put("host", hostPattern)
            put("port", port)
            put("protocol", protocol)
            put("file", "")
        }

        val newInclude = JsonArray(includeArray + newRule)
        val newScope = JsonObject(scope.toMutableMap().apply { put("include", newInclude) })
        val newTarget = JsonObject(target.toMutableMap().apply { put("scope", newScope) })
        val newRoot = JsonObject(root.toMutableMap().apply { put("target", newTarget) })

        return try {
            api.burpSuite().importProjectOptionsFromJson(newRoot.toString())
            Pair("Added scope rule for $host (+ subdomains, protocol: $protocol).", true)
        } catch (e: Exception) {
            Pair("Error reimporting scope JSON: ${e.message}", false)
        }
    }

    // ── remove_from_scope ─────────────────────────────────────────────────────

    private fun registerRemoveFromScope(server: Server, api: MontoyaApi, approvalManager: ApprovalManager, auditLogger: AuditLogger) {
        val toolName = "remove_from_scope"
        server.addTool(
            tool = Tool(
                name = toolName,
                description = "Removes a URL from Burp's target scope INCLUDE list by deleting the matching rule. " +
                    "Does NOT create an exclusion rule. Requires explicit user approval.",
                inputSchema = ToolSchema(
                    properties = buildJsonObject {
                        putJsonObject("url") { put("type", "string") }
                    },
                    required = listOf("url")
                )
            )
        ) { request ->
            try {
                val url = request.params.arguments?.get("url")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(listOf(TextContent("Error: 'url' required.")), true)

                val scheme = try { URI(url).scheme?.lowercase() } catch (e: Exception) { null }
                if (scheme != "http" && scheme != "https") {
                    return@addTool CallToolResult(listOf(TextContent("Error: URL must be http or https.")), true)
                }

                if (!approvalManager.requestApproval(ApprovalManager.ApprovalLevel.EXPLICIT_APPROVAL, toolName, url)) {
                    auditLogger.log(toolName, url, false, AuditLogger.Result.DENIED)
                    return@addTool CallToolResult(listOf(TextContent("DENIED: User did not approve scope change.")), true)
                }

                val result = removeIncludeRule(api, url)
                auditLogger.log(toolName, url, result.second, AuditLogger.Result.SUCCESS)
                CallToolResult(listOf(TextContent(result.first)))
            } catch (e: Exception) {
                auditLogger.log(toolName, "unknown", null, AuditLogger.Result.ERROR)
                CallToolResult(listOf(TextContent("Error: ${e.message}")), true)
            }
        }
    }

    /**
     * Removes a matching include rule from the scope JSON.
     *
     * Matches by:
     * - "prefix" field (simple scope mode): exact match after trailing-slash normalisation
     * - "host" field (advanced scope mode): exact or subdomain-pattern match on the host component
     */
    private fun removeIncludeRule(api: MontoyaApi, targetUrl: String): Pair<String, Boolean> {
        val exported = api.burpSuite().exportProjectOptionsAsJson("target.scope")
        val root = try { Json.parseToJsonElement(exported).jsonObject }
        catch (e: Exception) { return Pair("Error parsing scope JSON: ${e.message}", false) }

        val target = root["target"]?.jsonObject
            ?: return Pair("Error: no 'target' key in scope JSON.", false)
        val scope = target["scope"]?.jsonObject
            ?: return Pair("Error: no 'target.scope' key.", false)
        val includeArray = scope["include"]?.jsonArray
            ?: return Pair("No include rules found in scope.", false)

        val normalizedTarget = targetUrl.trimEnd('/')
        val targetHost = try { URI(targetUrl).host } catch (e: Exception) { null }

        val filtered = includeArray.filter { entry ->
            val obj = entry.jsonObject
            // Simple mode: match by "prefix" field
            val prefix = obj["prefix"]?.jsonPrimitive?.contentOrNull?.trimEnd('/')
            if (prefix != null) {
                return@filter prefix != normalizedTarget
            }
            // Advanced mode: match by "host" field — check if it resolves to same host
            val host = obj["host"]?.jsonPrimitive?.contentOrNull ?: return@filter true
            val hostWithoutSubdomainPattern = host.removePrefix("(.*\\.)?")
            val unescapedHost = hostWithoutSubdomainPattern.replace("\\.", ".")
            !(targetHost != null && unescapedHost.equals(targetHost, ignoreCase = true))
        }

        if (filtered.size == includeArray.size) {
            return Pair("No matching include rule found for: $targetUrl (nothing removed).", false)
        }

        val removedCount = includeArray.size - filtered.size
        val newScope = JsonObject(scope.toMutableMap().apply { put("include", JsonArray(filtered)) })
        val newTarget = JsonObject(target.toMutableMap().apply { put("scope", newScope) })
        val newRoot = JsonObject(root.toMutableMap().apply { put("target", newTarget) })

        return try {
            api.burpSuite().importProjectOptionsFromJson(newRoot.toString())
            Pair("Removed $removedCount include rule(s) matching: $targetUrl", true)
        } catch (e: Exception) {
            Pair("Error reimporting scope JSON: ${e.message}", false)
        }
    }
}
