package security

import burp.api.montoya.MontoyaApi

/**
 * Checks whether a given URL is within Burp Suite's configured target scope.
 *
 * Uses the direct Montoya API: api.scope().isInScope(url)
 * — no fragile JSON parsing of project options.
 *
 * This is a mandatory gate before network operations:
 * - start_crawl_and_scan: DENIED if target not in scope
 * - (future network tools): same enforcement
 *
 * Deny-by-default: if the scope check throws or fails, access is blocked.
 */
class ScopeChecker(private val api: MontoyaApi) {

    /**
     * Returns true if the given URL is within the project's target scope.
     * Delegates directly to api.scope().isInScope(url).
     *
     * On any error, returns false (deny-by-default).
     */
    fun isInScope(url: String): Boolean {
        return try {
            api.scope().isInScope(url)
        } catch (e: Exception) {
            api.logging().logToError("ScopeChecker: Error checking scope for '$url': ${e.message}")
            false // Deny by default on error
        }
    }

    /**
     * Extracts the host portion from a URL string.
     * Returns null if the URL is malformed.
     */
    fun extractHost(url: String): String? {
        return try {
            java.net.URI(url).host
        } catch (e: Exception) {
            null
        }
    }
}
