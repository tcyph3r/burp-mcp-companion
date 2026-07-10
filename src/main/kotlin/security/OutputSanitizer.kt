package security

/**
 * Sanitizes tool output to prevent prompt injection attacks.
 *
 * All tool outputs containing user-controlled data (HTTP history, site map,
 * comments, cookie metadata) are passed through this sanitizer before being
 * returned to the MCP client. This prevents malicious content in HTTP
 * responses or user notes from injecting MCP protocol commands.
 */
object OutputSanitizer {

    // Patterns that could be used for prompt injection via MCP protocol.
    // Each pair is (pattern, replacement description) for clarity.
    private val DANGEROUS_PATTERNS = listOf(
        Regex("""\{"jsonrpc"\s*:"""),
        Regex(""""method"\s*:\s*"tools/"""),
        Regex("""<tool_call>""", RegexOption.IGNORE_CASE),
        Regex("""</tool_call>""", RegexOption.IGNORE_CASE),
        Regex("""<function_calls>""", RegexOption.IGNORE_CASE),
        Regex("""</function_calls>""", RegexOption.IGNORE_CASE),
        Regex(""""method"\s*:\s*"resources/"""),
        Regex(""""method"\s*:\s*"prompts/"""),
        Regex(""""method"\s*:\s*"notifications/"""),
        Regex(""""method"\s*:\s*"initialize""""),
        Regex(""""jsonrpc"\s*:\s*"2\.0""""),
    )

    /**
     * Sanitizes a string by escaping dangerous prompt injection patterns.
     * Each character of a matched pattern is replaced with its Unicode escape
     * to break the pattern while preserving readability.
     */
    fun sanitize(text: String): String {
        var result = text
        for (pattern in DANGEROUS_PATTERNS) {
            result = pattern.replace(result) { match ->
                match.value.map { c ->
                    "\\u${c.code.toString(16).padStart(4, '0')}"
                }.joinToString("")
            }
        }
        return result
    }

    /**
     * Sanitizes a comment string: strips injection patterns AND enforces max length.
     */
    fun sanitizeComment(comment: String, maxLength: Int = 500): String {
        val cleaned = sanitize(comment)
        return if (cleaned.length > maxLength) cleaned.substring(0, maxLength) else cleaned
    }
}
