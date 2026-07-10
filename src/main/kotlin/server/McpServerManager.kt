package server

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.routing.*
import io.ktor.server.sse.*
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import security.AllowlistManager
import security.ApprovalManager
import security.AuditLogger
import security.RateLimiter
import security.ScopeChecker
import tools.*
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Manages the Ktor SSE server lifecycle for the MCP companion extension.
 *
 * Starts an embedded Netty server on 127.0.0.1:9877.
 *
 * The mcp() Ktor extension in SDK 0.13.0 takes:
 *   Route.mcp(path: String, handler: (ServerSSESession) -> Server)
 *
 * The handler is invoked per SSE session and must return a configured Server.
 * We register all tools on each new Server instance inside the factory lambda.
 */
class McpServerManager(private val api: MontoyaApi) {

    companion object {
        const val DEFAULT_PORT = 9877
        const val DEFAULT_HOST = "127.0.0.1"
        const val SERVER_NAME = "burp-mcp-companion"
        const val SERVER_VERSION = "1.0.0"
    }

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "mcp-companion-server").apply { isDaemon = true }
    }

    // Security components (shared across sessions — all thread-safe)
    internal val allowlistManager = AllowlistManager(api)
    internal val approvalManager = ApprovalManager(api, allowlistManager)
    private val scopeChecker = ScopeChecker(api)
    private val rateLimiter = RateLimiter()
    private val auditLogger = AuditLogger(api)

    // Task tracking (shared — ConcurrentHashMap)
    private val taskRegistry = TaskRegistry()

    fun start(port: Int = DEFAULT_PORT, host: String = DEFAULT_HOST) {
        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                api.logging().logToOutput("$SERVER_NAME: Starting MCP SSE server on $host:$port...")

                server = embeddedServer(Netty, port = port, host = host) {
                    install(SSE)
                    install(CORS) {
                        // SECURITY: Lock CORS to localhost only.
                        // A malicious local webpage reaching port 9877 could otherwise
                        // invoke tools against the user's targets without their knowledge.
                        allowHost("localhost", schemes = listOf("http", "https"))
                        allowHost("127.0.0.1", schemes = listOf("http", "https"))
                        allowMethod(HttpMethod.Post)
                        allowMethod(HttpMethod.Get)
                        allowMethod(HttpMethod.Options)
                        allowHeader(HttpHeaders.ContentType)
                        allowHeader(HttpHeaders.Accept)
                    }

                    routing {
                        // mcp(path, handler) — handler is a factory called once per SSE session.
                        // It must return a fully configured Server.
                        mcp("/sse") {
                            buildMcpServer()
                        }
                    }
                }

                server!!.start(wait = false)
                api.logging().logToOutput("$SERVER_NAME: MCP SSE server started on $host:$port")
                api.logging().logToOutput("$SERVER_NAME: SSE endpoint: http://$host:$port/sse")

            } catch (e: Exception) {
                api.logging().logToError("$SERVER_NAME: Failed to start server: ${e.message}")
            }
        }
    }

    fun stop() {
        try {
            api.logging().logToOutput("$SERVER_NAME: Shutting down...")
            server?.stop(1000, 5000)
            server = null
            taskRegistry.shutdown()
            executor.shutdown()
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow()
            }
            api.logging().logToOutput("$SERVER_NAME: Stopped cleanly.")
        } catch (e: Exception) {
            api.logging().logToError("$SERVER_NAME: Error during shutdown: ${e.message}")
            executor.shutdownNow()
        }
    }

    /**
     * Factory: called once per MCP session. Returns a Server with all tools registered.
     * Shared security components (approvalManager, rateLimiter, etc.) are thread-safe.
     */
    private fun buildMcpServer(): Server {
        val mcpServer = Server(
            serverInfo = Implementation(SERVER_NAME, SERVER_VERSION),
            options = ServerOptions(
                capabilities = ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = false)
                )
            )
        )

        SiteMapTool.register(mcpServer, api, approvalManager, auditLogger)
        ScannerTools.register(mcpServer, api, approvalManager, scopeChecker, rateLimiter, auditLogger, taskRegistry)
        AnnotationTools.register(mcpServer, api, auditLogger)
        ScopeTools.register(mcpServer, api, approvalManager, auditLogger)
        WebSocketTool.register(mcpServer)
        CookieTool.register(mcpServer, api, approvalManager, auditLogger)

        return mcpServer
    }
}
