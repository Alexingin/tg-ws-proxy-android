package com.amurcanov.tgwsproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.time.Duration.Companion.milliseconds
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

class ProxyService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null
    private var statsJob: Job? = null
    private var restartJob: Job? = null
    private var watchdogJob: Job? = null
    private var networkResetJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var screenReceiver: BroadcastReceiver? = null
    @Volatile private var currentNetwork: Network? = null
    @Volatile private var screenOffAtMs: Long = 0L
    private var lastTrafficBytes: Long = -1L
    private var lastTrafficAtMs: Long = 0L
    private var lastNotificationContent: String = ""
    private var lastNotificationAtMs: Long = 0L
    private var notificationStartedAtMs: Long = 0L
    @Volatile
    private var stopInProgress = false
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Saved intent extras for restart on kill / onTaskRemoved
    private var lastBindIp: String = "127.0.0.1"
    private var lastPort: Int = 1443
    private var lastIps: String = ""
    private var lastPoolSize: Int = 4
    private var lastCfEnabled: Boolean = true
    private var lastCfPriority: Boolean = true
    private var lastCfDomain: String = ""
    private var lastSecretKey: String = ""
    private var lastKeepAwake: Boolean = true
    private var lastVerbose: Boolean = false

    companion object {
        const val ACTION_START = "com.amurcanov.tgwsproxy.START"
        const val ACTION_STOP = "com.amurcanov.tgwsproxy.STOP"
        const val ACTION_RESTART = "com.amurcanov.tgwsproxy.RESTART"
        const val EXTRA_BIND_IP = "EXTRA_BIND_IP"
        const val EXTRA_PORT = "EXTRA_PORT"
        const val EXTRA_IPS = "EXTRA_IPS"
        const val EXTRA_POOL_SIZE = "EXTRA_POOL_SIZE"
        const val EXTRA_CFPROXY_ENABLED = "EXTRA_CFPROXY_ENABLED"
        const val EXTRA_CFPROXY_PRIORITY = "EXTRA_CFPROXY_PRIORITY"
        const val EXTRA_CFPROXY_DOMAIN = "EXTRA_CFPROXY_DOMAIN"
        const val EXTRA_SECRET_KEY = "EXTRA_SECRET_KEY"
        const val EXTRA_KEEP_AWAKE = "EXTRA_KEEP_AWAKE"
        const val EXTRA_VERBOSE = "EXTRA_VERBOSE"
        
        private const val NOTIFICATION_ID = 101
        private const val CHANNEL_ID = "TG_WS_Proxy_Service_v4"
        private const val TAG = "ProxyService"

        // Wakelock refresh interval (25 min, re-acquire before 30-min timeout)
        private const val WAKELOCK_TIMEOUT_MS = 30L * 60 * 1000
        private const val WAKELOCK_REFRESH_MS = 25L * 60 * 1000

        // Stats/notification update interval (экран включён / выключен)
        private const val STATS_UPDATE_MS = 3_000L
        private const val STATS_UPDATE_SCREEN_OFF_MS = 20_000L
        // Wakelock держим, пока Telegram активен: есть соединения или новые
        // подключения были недавно. Без активности отпускаем — телефон спит.
        private const val WAKELOCK_IDLE_RELEASE_SEC = 180
        private const val NOTIFICATION_MIN_UPDATE_MS = 3_000L
        private const val NATIVE_STOP_WAIT_MS = 3_000L

        // Сторожок: раз в N мс проверяем, что локальный порт принимает подключения.
        private const val WATCHDOG_INTERVAL_MS = 60_000L
        private const val WATCHDOG_CONNECT_TIMEOUT_MS = 2_000
        private const val WATCHDOG_FAILS_BEFORE_RESTART = 2
        // Сеть часто "дребезжит" при переключении — ждём, пока успокоится.
        private const val NETWORK_RESET_DEBOUNCE_MS = 1_500L
        // Сбрасывать пул при включении экрана, только если он был выключен дольше этого.
        private const val SCREEN_OFF_RESET_MIN_MS = 60_000L

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning
        private val _isVerifiedRunning = MutableStateFlow(false)
        val isVerifiedRunning: StateFlow<Boolean> = _isVerifiedRunning
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                LogManager.clearLogs()
                val bindIp = intent.getStringExtra(EXTRA_BIND_IP) ?: "127.0.0.1"
                val port = intent.getIntExtra(EXTRA_PORT, 1443)
                val ips = intent.getStringExtra(EXTRA_IPS) ?: ""
                val poolSize = intent.getIntExtra(EXTRA_POOL_SIZE, 4)
                val cfEnabled = intent.getBooleanExtra(EXTRA_CFPROXY_ENABLED, true)
                val cfPriority = intent.getBooleanExtra(EXTRA_CFPROXY_PRIORITY, true)
                val cfDomain = intent.getStringExtra(EXTRA_CFPROXY_DOMAIN) ?: ""
                val secretKey = intent.getStringExtra(EXTRA_SECRET_KEY) ?: ""
                lastKeepAwake = intent.getBooleanExtra(EXTRA_KEEP_AWAKE, true)
                lastVerbose = intent.getBooleanExtra(EXTRA_VERBOSE, false)
                startProxy(bindIp, port, ips, poolSize, cfEnabled, cfPriority, cfDomain, secretKey)
            }
            ACTION_STOP -> {
                stopProxy()
            }
            ACTION_RESTART -> {
                restartProxy()
            }
            null -> {
                // Service restarted by system after being killed (START_REDELIVER_INTENT)
                // If we had saved params, try to restart
                if (lastPort > 0 && lastSecretKey.isNotEmpty()) {
                    Log.w(TAG, "Service restarted by system, re-starting proxy")
                    startProxy(lastBindIp, lastPort, lastIps, lastPoolSize, lastCfEnabled, lastCfPriority, lastCfDomain, lastSecretKey)
                } else {
                    stopSelf()
                }
            }
        }
        // START_REDELIVER_INTENT: if the system kills the service, it will restart it
        // and re-deliver the last intent, so we don't lose the config.
        return START_REDELIVER_INTENT
    }

    private fun isPortAvailable(bindIp: String, port: Int): Boolean {
        return try {
            ServerSocket().use { socket ->
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(InetAddress.getByName(bindIp), port))
                true
            }
        } catch (_: Exception) {
            // (Если надо, то тут может быть IOException или SecurityException) (IOException добавляет новый import так что "_", по-моему, лучше)
            return false
        }
    }


    private fun startProxy(bindIp: String, port: Int, ips: String, poolSize: Int = 4,
                           cfEnabled: Boolean = true, cfPriority: Boolean = true,
                           cfDomain: String = "", secretKey: String = "") {
        if (_isRunning.value || stopInProgress) return
        _isVerifiedRunning.value = false

        // Save params for restart
        lastBindIp = bindIp
        lastPort = port
        lastIps = ips
        lastPoolSize = poolSize
        lastCfEnabled = cfEnabled
        lastCfPriority = cfPriority
        lastCfDomain = cfDomain
        lastSecretKey = secretKey
        notificationStartedAtMs = System.currentTimeMillis()
        lastNotificationContent = getString(R.string.notification_starting)
        lastNotificationAtMs = notificationStartedAtMs

        val notification = createNotification(lastNotificationContent)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        acquireWakeLock()
        stopInProgress = false
        
        // Start Go proxy in a separate thread with error handling
        Thread({
            val canObtainPort = isPortAvailable(bindIp, port)
            if (!canObtainPort) {
                val str = getString(R.string.port_is_not_available, port)
                serviceScope.launch(Dispatchers.Main) {
                    Toast.makeText(this@ProxyService, str, Toast.LENGTH_SHORT).show()
                    updateNotification(str, force = true)
                    stopProxy()
                }
                return@Thread
            }

            try {
                NativeProxy.setPoolSize(poolSize)
                NativeProxy.setCfProxyCacheDir(cacheDir.absolutePath)
                NativeProxy.setCfProxyConfig(cfEnabled, cfPriority, cfDomain)
                // Подробные (debug) логи движка — только если включены в фильтре логов:
                // каждая строка уходит в logcat и стоит CPU.
                val result = NativeProxy.startProxy(bindIp, port, ips, secretKey, if (lastVerbose) 1 else 0)
                if (result == 0) {
                    serviceScope.launch {
                        if (!stopInProgress) {
                            updateRunningState(true)
                            _isVerifiedRunning.value = true
                            updateNotification(getString(R.string.notification_running), force = true)
                            Log.i(TAG, "Proxy ready: listening on port $port")
                            startMonitors()
                        }
                    }
                } else {
                    Log.e(TAG, "StartProxy returned error code: $result")
                    serviceScope.launch {
                        updateNotification(getString(R.string.notification_start_error_code, result), force = true)
                        delay(3000.milliseconds)
                        stopProxy()
                    }
                }
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to start proxy via JNA", e)
                serviceScope.launch {
                    updateNotification(getString(R.string.notification_error, e.message ?: ""), force = true)
                    delay(3000.milliseconds)
                    stopProxy()
                }
            }
        }, "ProxyStart").apply {
            isDaemon = true
            start()
        }

                    // Don't stop — it might start slightly later; let the user decide
        // Stats updater. Notification updates are throttled so the system keeps
        // a stable foreground entry instead of constantly reordering it.
        statsJob = serviceScope.launch {
            // WakeLock refresh sub-job: re-acquire before system timeout
            launch {
                while (isActive) {
                    delay(WAKELOCK_REFRESH_MS.milliseconds)
                    refreshWakeLock()
                }
            }

            while (isActive) {
                val interactive = isScreenOn()
                delay((if (interactive) STATS_UPDATE_MS else STATS_UPDATE_SCREEN_OFF_MS).milliseconds)
                if (_isRunning.value && !stopInProgress) {
                    updateSmartWakeLock()
                    // При выключенном экране уведомление никто не видит — не обновляем.
                    if (!interactive) continue
                    try {
                        val rawStats = NativeProxy.getStats() ?: continue
                        val upRaw = extractStat(rawStats, "up=")
                        val downRaw = extractStat(rawStats, "down=")
                        val activeConns = extractStat(rawStats, "active=")
                        
                        val totalBytes = parseHumanBytes(upRaw) + parseHumanBytes(downRaw)
                        val active = activeConns.toIntOrNull() ?: 0
                        val text = getString(R.string.notification_traffic, formatBytes(totalBytes), active)
                        updateNotification(text)
                    } catch (e: Exception) {
                        Log.w(TAG, "Stats update failed", e)
                    }
                }
            }
        }
    }

    private fun updateNotification(content: String, force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!force) {
            if (content == lastNotificationContent) return
            if (lastNotificationAtMs != 0L && now - lastNotificationAtMs < NOTIFICATION_MIN_UPDATE_MS) return
        }

        lastNotificationContent = content
        lastNotificationAtMs = now
        try {
            val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
            manager?.notify(NOTIFICATION_ID, createNotification(content))
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update notification", e)
        }
    }

    private fun restartProxy() {
        if (restartJob?.isActive == true) return
        if (lastPort <= 0 || lastSecretKey.isEmpty()) {
            Log.w(TAG, "Restart requested without saved proxy configuration")
            return
        }

        restartJob = serviceScope.launch {
            Log.i(TAG, "Restarting proxy from notification")
            updateNotification(getString(R.string.notification_restarting), force = true)

            statsJob?.cancel()
            statsJob = null
            stopMonitors()

            requestNativeStop("restart")
            releaseWakeLock()
            updateRunningState(false)
            delay(350.milliseconds)

            startProxy(
                bindIp = lastBindIp,
                port = lastPort,
                ips = lastIps,
                poolSize = lastPoolSize,
                cfEnabled = lastCfEnabled,
                cfPriority = lastCfPriority,
                cfDomain = lastCfDomain,
                secretKey = lastSecretKey
            )
        }
    }

    private fun extractStat(stats: String, key: String): String {
        val idx = stats.indexOf(key)
        if (idx == -1) return "0B"
        val start = idx + key.length
        val end = stats.indexOf(" ", start)
        return if (end == -1) stats.substring(start) else stats.substring(start, end)
    }
    
    private fun parseHumanBytes(s: String): Double {
        val num = s.replace(Regex("[^0-9.]"), "").toDoubleOrNull() ?: 0.0
        return when {
            s.endsWith("TB") -> num * 1024.0 * 1024 * 1024 * 1024
            s.endsWith("GB") -> num * 1024.0 * 1024 * 1024
            s.endsWith("MB") -> num * 1024.0 * 1024
            s.endsWith("KB") -> num * 1024.0
            else -> num
        }
    }
    
    private fun formatBytes(bytes: Double): String {
        if (bytes < 1024) return "%.0fB".format(bytes)
        if (bytes < 1024 * 1024) return "%.1fKB".format(bytes / 1024)
        if (bytes < 1024 * 1024 * 1024) return "%.1fMB".format(bytes / (1024 * 1024))
        return "%.2fGB".format(bytes / (1024 * 1024 * 1024))
    }

    private fun stopProxy() {
        if (stopInProgress) return
        stopInProgress = true
        stopMonitors()
        restartJob?.cancel()
        restartJob = null
        statsJob?.cancel()
        statsJob = null
        serviceScope.launch {
            updateNotification(getString(R.string.notification_stopping), force = true)
            requestNativeStop("stop")
            releaseWakeLock()
            updateRunningState(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
            stopSelf()
        }
    }

    private suspend fun requestNativeStop(reason: String): Boolean {
        val completed = CompletableDeferred<Unit>()
        Thread({
            try {
                NativeProxy.stopProxy()
            } catch (e: Exception) {
                Log.w(TAG, "StopProxy failed during $reason", e)
            } finally {
                completed.complete(Unit)
            }
        }, "ProxyStop-$reason").apply {
            isDaemon = true
            start()
        }

        val finished = withTimeoutOrNull(NATIVE_STOP_WAIT_MS.milliseconds) {
            completed.await()
            true
        } ?: false

        if (!finished) {
            Log.w(TAG, "Native stop is still running after ${NATIVE_STOP_WAIT_MS}ms during $reason")
        }
        return finished
    }

    /**
     * Called when the user swipes the app from recents.
     * Without this, the service would be killed on many OEM Androids.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        if (_isRunning.value) {
            Log.w(TAG, "onTaskRemoved: proxy is running, service stays alive")
            // The service continues because stopWithTask=false in manifest
            // No action needed — the service keeps running.
        }
    }

    private fun isScreenOn(): Boolean = try {
        (getSystemService(POWER_SERVICE) as PowerManager).isInteractive
    } catch (_: Exception) {
        true
    }

    /**
     * «Умный» wakelock (issue #253): держим его, только пока Telegram активен —
     * были новые подключения или шёл трафик в последние минуты. Просто
     * открытое, но молчащее соединение не считается: иначе телефон не спал бы
     * никогда. Как только Telegram снова что-то передаст, захватим заново.
     */
    private fun updateSmartWakeLock() {
        if (!lastKeepAwake) return
        val now = android.os.SystemClock.elapsedRealtime()
        val needAwake = try {
            val idle = NativeProxy.clientIdleSeconds()
            val traffic = NativeProxy.trafficBytes()
            if (traffic != lastTrafficBytes) {
                lastTrafficBytes = traffic
                lastTrafficAtMs = now
            }
            val trafficRecent = now - lastTrafficAtMs < WAKELOCK_IDLE_RELEASE_SEC * 1000L
            idle in 0 until WAKELOCK_IDLE_RELEASE_SEC || trafficRecent
        } catch (_: Throwable) {
            true
        }
        val held = wakeLock?.isHeld == true
        if (needAwake && !held) {
            acquireWakeLock()
        } else if (!needAwake && held) {
            Log.d(TAG, "WakeLock released: Telegram idle")
            releaseWakeLock()
        }
    }

    private fun acquireWakeLock() {
        if (!lastKeepAwake) {
            Log.d(TAG, "WakeLock disabled in settings")
            return
        }
        try {
            val powerManager = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "TgWsProxy::ServiceWakeLock"
            ).apply {
                // Acquire with timeout. System may ignore indefinite wakelocks.
                acquire(WAKELOCK_TIMEOUT_MS)
            }
            Log.d(TAG, "WakeLock acquired (${WAKELOCK_TIMEOUT_MS / 60000}min)")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to acquire WakeLock", e)
        }
    }

    /**
     * Periodically refresh wakelock to prevent system from expiring it.
     */
    private fun refreshWakeLock() {
        if (!lastKeepAwake) return
        // Отпущен «умной» логикой — не захватываем заново по таймеру.
        if (wakeLock?.isHeld != true) return
        try {
            wakeLock?.let {
                if (it.isHeld) {
                    it.release()
                }
            }
            val powerManager = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "TgWsProxy::ServiceWakeLock"
            ).apply {
                acquire(WAKELOCK_TIMEOUT_MS)
            }
            Log.d(TAG, "WakeLock refreshed")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to refresh WakeLock", e)
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let {
                if (it.isHeld) {
                    it.release()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to release WakeLock", e)
        }
        wakeLock = null
    }

    private fun updateRunningState(isRunning: Boolean) {
        _isRunning.value = isRunning
        if (!isRunning) {
            _isVerifiedRunning.value = false
        }
        ProxyTileService.requestSync(this)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_description)
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
            manager?.createNotificationChannel(serviceChannel)
        }
    }

    private fun createNotification(content: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this, 1, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, ProxyService::class.java).apply {
            action = ACTION_STOP
        }
        val restartIntent = Intent(this, ProxyService::class.java).apply {
            action = ACTION_RESTART
        }
        val restartPendingIntent = PendingIntent.getService(
            this, 2, restartIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Telegram WS Proxy")
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(openPendingIntent) // Tap notification → open app
            .addAction(android.R.drawable.ic_popup_sync, getString(R.string.notification_restart), restartPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, getString(R.string.notification_disconnect), stopPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setWhen(notificationStartedAtMs.takeIf { it > 0L } ?: System.currentTimeMillis())
            .setShowWhen(false)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    override fun onDestroy() {
        stopMonitors()
        restartJob?.cancel()
        restartJob = null
        statsJob?.cancel()
        statsJob = null
        releaseWakeLock()
        if (_isRunning.value) {
            updateRunningState(false)
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    // -----------------------------------------------------------------------
    // Мониторы: смена сети, пробуждение экрана, сторожок локального порта.
    // -----------------------------------------------------------------------

    private fun startMonitors() {
        stopMonitors()
        registerNetworkCallback()
        registerScreenReceiver()
        startWatchdog()
    }

    private fun stopMonitors() {
        watchdogJob?.cancel()
        watchdogJob = null
        networkResetJob?.cancel()
        networkResetJob = null
        networkCallback?.let { cb ->
            try {
                (getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager)
                    .unregisterNetworkCallback(cb)
            } catch (_: Exception) {
            }
        }
        networkCallback = null
        currentNetwork = null
        screenReceiver?.let { r ->
            try {
                unregisterReceiver(r)
            } catch (_: Exception) {
            }
        }
        screenReceiver = null
    }

    /** Сброс состояния движка с антидребезгом. */
    private fun scheduleNetworkReset(reason: String) {
        networkResetJob?.cancel()
        networkResetJob = serviceScope.launch {
            delay(NETWORK_RESET_DEBOUNCE_MS.milliseconds)
            if (!_isRunning.value || stopInProgress) return@launch
            try {
                val r = NativeProxy.resetNetworkState()
                Log.i(TAG, "Network state reset ($reason) -> $r")
            } catch (e: Throwable) {
                Log.w(TAG, "resetNetworkState failed", e)
            }
        }
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val prev = currentNetwork
                currentNetwork = network
                // Первый вызов сразу после регистрации — это текущая сеть, не смена.
                if (prev != null && prev != network) {
                    scheduleNetworkReset("network switched")
                }
            }

            override fun onLost(network: Network) {
                if (network == currentNetwork) {
                    currentNetwork = null
                    // Сеть пропала: при появлении новой onAvailable увидит prev == null,
                    // поэтому сбрасываем здесь (сработает после антидребезга).
                    scheduleNetworkReset("network lost")
                }
            }
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                cm.registerDefaultNetworkCallback(cb)
            } else {
                val req = NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build()
                cm.registerNetworkCallback(req, cb)
            }
            networkCallback = cb
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback", e)
        }
    }

    private fun registerScreenReceiver() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_OFF -> screenOffAtMs = System.currentTimeMillis()
                    Intent.ACTION_SCREEN_ON -> {
                        val offFor = if (screenOffAtMs > 0) System.currentTimeMillis() - screenOffAtMs else 0L
                        screenOffAtMs = 0L
                        if (offFor >= SCREEN_OFF_RESET_MIN_MS) {
                            scheduleNetworkReset("screen on after ${offFor / 1000}s")
                        }
                    }
                }
            }
        }
        try {
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
            }
            // SCREEN_ON/OFF шлёт система — они приходят и в неэкспортируемый ресивер.
            ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
            screenReceiver = receiver
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register screen receiver", e)
        }
    }

    /**
     * Если локальный порт перестал принимать подключения (движок завис/упал),
     * Telegram не может достучаться до прокси. Два провала подряд — перезапуск,
     * то же самое, что нажать «Перезапуск» в уведомлении.
     */
    private fun startWatchdog() {
        watchdogJob = serviceScope.launch {
            var fails = 0
            while (isActive) {
                delay(WATCHDOG_INTERVAL_MS.milliseconds)
                if (!_isRunning.value || stopInProgress || restartJob?.isActive == true) {
                    fails = 0
                    continue
                }
                val host = if (lastBindIp == "0.0.0.0" || lastBindIp == "::") "127.0.0.1" else lastBindIp
                val alive = try {
                    Socket().use { s ->
                        s.connect(InetSocketAddress(host, lastPort), WATCHDOG_CONNECT_TIMEOUT_MS)
                    }
                    true
                } catch (_: Exception) {
                    false
                }
                if (alive) {
                    fails = 0
                } else {
                    fails++
                    Log.w(TAG, "Watchdog: port $lastPort not answering ($fails/$WATCHDOG_FAILS_BEFORE_RESTART)")
                    if (fails >= WATCHDOG_FAILS_BEFORE_RESTART) {
                        fails = 0
                        withContext(Dispatchers.Main) { restartProxy() }
                    }
                }
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }
}
