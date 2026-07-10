package security

import burp.api.montoya.MontoyaApi
import javax.swing.JOptionPane
import javax.swing.SwingUtilities
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Manages user approval dialogs for MCP tool operations.
 *
 * Approval levels:
 * - NO_APPROVAL: Low-risk UI ops (highlight_request, add_comment, get_scope, get_scan_status)
 * - DATA_ACCESS: READ ops returning sensitive data (get_sitemap, get_cookies)
 *   → auto-approved if host is in allowlist, otherwise dialog
 * - EXPLICIT_APPROVAL: WRITE/NETWORK ops (start_crawl_and_scan, add_to_scope,
 *   remove_from_scope) → ALWAYS shows dialog, never auto-approved
 *
 * SECURITY: On 60-second timeout, the dialog auto-DENIES. Never auto-approves.
 */
class ApprovalManager(
    private val api: MontoyaApi,
    private val allowlistManager: AllowlistManager
) {

    companion object {
        private const val TIMEOUT_SECONDS = 60L
    }

    // UI-controlled flags — toggled from the companion tab
    @Volatile var autoApproveDataAccess: Boolean = false
    @Volatile var autoApproveAll: Boolean = false

    enum class ApprovalLevel {
        NO_APPROVAL,
        DATA_ACCESS,
        EXPLICIT_APPROVAL
    }

    /**
     * Requests approval for an operation. Returns true only if explicitly approved.
     */
    fun requestApproval(level: ApprovalLevel, toolName: String, target: String): Boolean {
        return when (level) {
            ApprovalLevel.NO_APPROVAL -> true

            ApprovalLevel.DATA_ACCESS -> {
                if (autoApproveAll || autoApproveDataAccess) return true
                val host = extractHost(target)
                if (host != null && allowlistManager.isAllowed(host)) {
                    true
                } else {
                    showApprovalDialog(toolName, target, isDataAccess = true)
                }
            }

            ApprovalLevel.EXPLICIT_APPROVAL -> {
                if (autoApproveAll) return true
                showApprovalDialog(toolName, target, isDataAccess = false)
            }
        }
    }

    private fun showApprovalDialog(toolName: String, target: String, isDataAccess: Boolean): Boolean {
        val future = CompletableFuture<Boolean>()

        val title = if (isDataAccess) "MCP Data Access Request" else "MCP Operation Approval Required"

        val message = buildString {
            append("MCP tool '")
            append(toolName)
            append("' is requesting ")
            if (isDataAccess) {
                append("access to data from:\n\n")
            } else {
                append("permission to perform an operation on:\n\n")
            }
            append("  Target: ")
            append(target)
            append("\n\n")
            if (!isDataAccess) {
                append("⚠️ This is a WRITE/NETWORK operation.\n\n")
            }
            append("Do you want to allow this?")
        }

        try {
            SwingUtilities.invokeAndWait {
                val parentFrame = api.userInterface().swingUtils().suiteFrame()
                val result = JOptionPane.showConfirmDialog(
                    parentFrame,
                    message,
                    title,
                    JOptionPane.YES_NO_OPTION,
                    if (isDataAccess) JOptionPane.QUESTION_MESSAGE else JOptionPane.WARNING_MESSAGE
                )
                future.complete(result == JOptionPane.YES_OPTION)
            }
        } catch (e: Exception) {
            api.logging().logToError("ApprovalManager: Dialog error: ${e.message}")
            // Security: auto-DENY on error — never auto-approve
            future.complete(false)
        }

        return try {
            future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            // Security: auto-DENY on timeout — never auto-approve
            api.logging().logToOutput("ApprovalManager: Approval timed out after ${TIMEOUT_SECONDS}s for '$toolName' on '$target'. Auto-denied.")
            false
        } catch (e: Exception) {
            // Security: auto-DENY on any error — never auto-approve
            false
        }
    }

    private fun extractHost(target: String): String? {
        return try {
            java.net.URI(target).host
        } catch (e: Exception) {
            target.takeIf { it.isNotBlank() && !it.contains("/") }
        }
    }
}
