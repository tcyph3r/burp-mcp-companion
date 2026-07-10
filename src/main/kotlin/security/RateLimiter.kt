package security

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Per-host token bucket rate limiter for network-hitting MCP tools.
 *
 * Different tool categories have different rate limits:
 * - Scanning tools (start_crawl_and_scan): 2 requests per host per minute
 * - Default network tools: 10 requests per host per minute
 *
 * Thread-safe via ConcurrentHashMap + AtomicLong timestamps.
 * Stale buckets are pruned periodically to prevent memory leaks.
 */
class RateLimiter {

    companion object {
        const val SCAN_RATE_PER_MINUTE = 2
        const val DEFAULT_RATE_PER_MINUTE = 10
        private const val WINDOW_MS = 60_000L // 1 minute
        private const val PRUNE_INTERVAL_MS = 300_000L // 5 minutes
    }

    private data class TokenBucket(
        val timestamps: MutableList<Long> = mutableListOf(),
        val maxTokens: Int
    )

    // Key: "category:host" e.g. "scan:example.com"
    private val buckets = ConcurrentHashMap<String, TokenBucket>()
    private val lastPrune = AtomicLong(System.currentTimeMillis())

    /**
     * Attempts to consume a token for the given host and category.
     *
     * @param host The target host
     * @param category Tool category: "scan" or "default"
     * @return null if allowed, or an error message with retry-after time if rate limited
     */
    fun tryAcquire(host: String, category: String = "default"): String? {
        pruneIfNeeded()

        val maxRate = when (category) {
            "scan" -> SCAN_RATE_PER_MINUTE
            else -> DEFAULT_RATE_PER_MINUTE
        }

        val key = "$category:${host.lowercase()}"
        val now = System.currentTimeMillis()
        val windowStart = now - WINDOW_MS

        val bucket = buckets.computeIfAbsent(key) { TokenBucket(maxTokens = maxRate) }

        synchronized(bucket) {
            // Remove timestamps outside the current window
            bucket.timestamps.removeAll { it < windowStart }

            if (bucket.timestamps.size >= maxRate) {
                // Rate limited — calculate retry-after
                val oldestInWindow = bucket.timestamps.minOrNull() ?: now
                val retryAfterMs = (oldestInWindow + WINDOW_MS) - now
                val retryAfterSecs = (retryAfterMs / 1000).coerceAtLeast(1)
                return "Rate limit exceeded for host '$host' ($maxRate requests/minute for $category). " +
                    "Try again in $retryAfterSecs seconds."
            }

            // Allowed — record this request
            bucket.timestamps.add(now)
            return null
        }
    }

    /**
     * Prune stale buckets every 5 minutes to prevent memory leaks.
     */
    private fun pruneIfNeeded() {
        val now = System.currentTimeMillis()
        val last = lastPrune.get()
        if (now - last > PRUNE_INTERVAL_MS && lastPrune.compareAndSet(last, now)) {
            val windowStart = now - WINDOW_MS
            buckets.entries.removeIf { (_, bucket) ->
                synchronized(bucket) {
                    bucket.timestamps.removeAll { it < windowStart }
                    bucket.timestamps.isEmpty()
                }
            }
        }
    }
}
