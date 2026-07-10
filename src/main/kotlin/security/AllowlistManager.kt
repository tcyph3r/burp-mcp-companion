package security

import burp.api.montoya.MontoyaApi
import java.util.concurrent.CopyOnWriteArraySet

/**
 * Manages an in-memory allowlist of hosts that are auto-approved for
 * READ operations (get_sitemap, get_cookies). Hosts in this list skip
 * the user approval dialog for data-access operations.
 *
 * WRITE/NETWORK operations (start_crawl_and_scan, add_to_scope, etc.)
 * ALWAYS require explicit approval regardless of this allowlist.
 *
 * SECURITY: Patterns are matched with simple String.equals() / String.endsWith()
 * — never compiled as Regex. Storing user-controlled strings and compiling them
 * as regex would create a regex injection risk.
 */
class AllowlistManager(private val api: MontoyaApi) {

    companion object {
        private const val SETTINGS_KEY = "mcp_companion_auto_approve_hosts"
        private const val SEPARATOR = "|"
    }

    private val allowedHosts = CopyOnWriteArraySet<String>()

    init {
        load()
    }

    /**
     * Checks if a host is in the auto-approve allowlist.
     *
     * Matching uses simple string operations (no regex):
     * - Exact match: "example.com" matches "example.com"
     * - Wildcard prefix: "*.example.com" matches "foo.example.com" and "example.com"
     */
    fun isAllowed(host: String): Boolean {
        val normalizedHost = host.lowercase().trim()
        return allowedHosts.any { pattern ->
            if (pattern.startsWith("*.")) {
                // Wildcard: *.example.com
                // Simple string suffix check — NOT regex
                val domain = pattern.removePrefix("*.")
                normalizedHost == domain || normalizedHost.endsWith(".$domain")
            } else {
                // Exact match — simple string equals
                normalizedHost == pattern
            }
        }
    }

    fun addHost(hostPattern: String) {
        val normalized = hostPattern.lowercase().trim()
        if (normalized.isNotEmpty()) {
            allowedHosts.add(normalized)
            save()
        }
    }

    fun removeHost(hostPattern: String) {
        allowedHosts.remove(hostPattern.lowercase().trim())
        save()
    }

    fun getAllowedHosts(): Set<String> = allowedHosts.toSet()

    private fun load() {
        try {
            val stored = api.persistence().extensionData().getString(SETTINGS_KEY)
            if (!stored.isNullOrBlank()) {
                stored.split(SEPARATOR)
                    .map { it.trim().lowercase() }
                    .filter { it.isNotEmpty() }
                    .forEach { allowedHosts.add(it) }
            }
        } catch (e: Exception) {
            api.logging().logToError("AllowlistManager: Failed to load settings: ${e.message}")
        }
    }

    private fun save() {
        try {
            val serialized = allowedHosts.joinToString(SEPARATOR)
            api.persistence().extensionData().setString(SETTINGS_KEY, serialized)
        } catch (e: Exception) {
            api.logging().logToError("AllowlistManager: Failed to save settings: ${e.message}")
        }
    }
}
