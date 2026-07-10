package server

import burp.api.montoya.scanner.Crawl
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Tracks active scanner tasks (Crawl handles) returned by the Montoya API.
 * 
 * Since the Montoya API doesn't provide a way to list all running tasks,
 * we store the returned handles here when a scan is started, allowing
 * get_scan_status to poll them later.
 */
class TaskRegistry {
    
    data class TaskInfo(
        val crawl: Crawl,
        val targetUrl: String,
        val startTimeMs: Long = System.currentTimeMillis()
    )
    
    // Keyed by a generated UUID string for each task
    private val tasks = ConcurrentHashMap<String, TaskInfo>()
    
    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "task-registry-pruner").apply { isDaemon = true }
    }
    
    init {
        // Prune tasks older than 1 hour every 5 minutes to prevent memory leaks
        scheduler.scheduleAtFixedRate({
            val oneHourAgo = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(1)
            tasks.entries.removeIf { it.value.startTimeMs < oneHourAgo }
        }, 5, 5, TimeUnit.MINUTES)
    }

    /**
     * Registers a new crawl task.
     * @return The generated task ID
     */
    fun register(taskId: String, crawl: Crawl, targetUrl: String) {
        tasks[taskId] = TaskInfo(crawl, targetUrl)
    }

    /**
     * Retrieves all tracked tasks.
     */
    fun getAllTasks(): Map<String, TaskInfo> = tasks.toMap()
    
    /**
     * Shuts down the background pruner.
     */
    fun shutdown() {
        scheduler.shutdownNow()
    }
}
