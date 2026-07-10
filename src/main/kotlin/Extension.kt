import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import server.McpServerManager
import ui.CompanionTab
import javax.swing.SwingUtilities

/**
 * Burp Suite MCP Companion Server Extension
 *
 * Runs a separate MCP SSE server on port 9877, exposing 9 tools that are
 * MISSING from the official burp-mcp-all.jar (port 9876). The two extensions
 * are designed to run side by side.
 *
 * Tools provided:
 *   1. get_sitemap
 *   2. start_crawl_and_scan
 *   3. get_scan_status
 *   4. highlight_request
 *   5. add_comment
 *   6. get_scope
 *   7. add_to_scope
 *   8. remove_from_scope
 *   9. get_cookies
 */
class Extension : BurpExtension {

    private var serverManager: McpServerManager? = null

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("MCP Companion Server")

        api.logging().logToOutput("=== MCP Companion Server Extension ===")
        api.logging().logToOutput("Initializing companion MCP server on port ${McpServerManager.DEFAULT_PORT}...")

        val manager = McpServerManager(api)
        serverManager = manager
        manager.start()

        // Register the UI tab on the Swing thread
        SwingUtilities.invokeLater {
            val tab = CompanionTab(manager)
            api.userInterface().registerSuiteTab("MCP Companion", tab)
        }

        api.extension().registerUnloadingHandler {
            api.logging().logToOutput("Unloading extension...")
            serverManager?.stop()
            serverManager = null
        }
    }
}
