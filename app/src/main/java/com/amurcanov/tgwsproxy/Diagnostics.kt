package com.amurcanov.tgwsproxy

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.app.Application
import android.content.Context
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Диагностика «почему прокси умер»:
 *  - причины завершения прошлых процессов из Android (ApplicationExitInfo, API 30+):
 *    убит системой, нехватка памяти, принудительная остановка, сбой и т.д.;
 *  - падение Kotlin-кода (uncaught exception) и паника Rust-движка — пишутся
 *    в файл и показываются при следующем запуске.
 * Всё выводится в лог с тегом TgWsProxy (видно во вкладке логов) и в отчёт.
 */
object Diagnostics {
    private const val TAG = "TgWsProxy"
    private const val PREFS = "diagnostics"
    private const val KEY_LAST_EXIT_TS = "last_exit_ts"
    private const val CRASH_FILE = "last_crash.txt"
    const val PANIC_FILE = "last_panic.txt"

    private val timeFormat = SimpleDateFormat("dd.MM HH:mm:ss", Locale.US)

    fun installCrashHandler(app: Application) {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            try {
                val sw = StringWriter()
                error.printStackTrace(PrintWriter(sw))
                val text = "${timeFormat.format(Date())} thread=${thread.name} " +
                    "version=${BuildConfig.VERSION_NAME}\n$sw"
                File(app.filesDir, CRASH_FILE).writeText(text.take(16_000))
            } catch (_: Throwable) {
            }
            previous?.uncaughtException(thread, error)
        }
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun reasonName(reason: Int): String = when (reason) {
        ApplicationExitInfo.REASON_ANR -> "ANR (приложение зависло)"
        ApplicationExitInfo.REASON_CRASH -> "сбой приложения (Kotlin)"
        ApplicationExitInfo.REASON_CRASH_NATIVE -> "сбой движка (native)"
        ApplicationExitInfo.REASON_DEPENDENCY_DIED -> "умер связанный процесс"
        ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "система: слишком много ресурсов"
        ApplicationExitInfo.REASON_EXIT_SELF -> "приложение завершилось само"
        ApplicationExitInfo.REASON_INITIALIZATION_FAILURE -> "ошибка инициализации"
        ApplicationExitInfo.REASON_LOW_MEMORY -> "система: нехватка памяти"
        ApplicationExitInfo.REASON_OTHER -> "система: другая причина"
        ApplicationExitInfo.REASON_PERMISSION_CHANGE -> "изменены разрешения"
        ApplicationExitInfo.REASON_SIGNALED -> "убит сигналом (часто — менеджер батареи прошивки)"
        ApplicationExitInfo.REASON_USER_REQUESTED -> "остановлен пользователем / «Остановить»"
        ApplicationExitInfo.REASON_USER_STOPPED -> "принудительно остановлен"
        14 -> "система: заморожен" // REASON_FREEZER (API 33)
        15 -> "изменилось состояние пакета" // REASON_PACKAGE_STATE_CHANGE (API 34)
        16 -> "приложение обновлено" // REASON_PACKAGE_UPDATED (API 34)
        else -> "неизвестно ($reason)"
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun describe(e: ApplicationExitInfo): String {
        val desc = e.description?.takeIf { it.isNotBlank() }?.let { " — $it" } ?: ""
        val raw = e.description.orEmpty().lowercase(Locale.US)
        // «o-kill» / «oplus» — собственный менеджер процессов OnePlus/OPPO/realme.
        val reason = if ("o-kill" in raw || "oplus" in raw || "athena" in raw) {
            "выгружен прошивкой OnePlus/OPPO"
        } else {
            reasonName(e.reason)
        }
        return "${timeFormat.format(Date(e.timestamp))}: $reason$desc " +
            "(status=${e.status}, importance=${e.importance})"
    }

    /** Последние причины завершения (для отчёта). */
    fun recentExits(context: Context, max: Int = 5): List<String> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return emptyList()
        return try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            am.getHistoricalProcessExitReasons(context.packageName, 0, max).map { describe(it) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Вывести в лог новые (ещё не показанные) причины завершения, а также
     * сохранённые сбои Kotlin и паники движка.
     */
    fun reportNewExits(context: Context) {
        val app = context.applicationContext
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                val lastSeen = prefs.getLong(KEY_LAST_EXIT_TS, 0L)
                val am = app.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                val exits = am.getHistoricalProcessExitReasons(app.packageName, 0, 10)
                    .filter { it.timestamp > lastSeen }
                    .sortedBy { it.timestamp }
                for (e in exits) {
                    Log.w(TAG, "[WARN] Прошлый процесс завершён: ${describe(e)}")
                }
                exits.maxOfOrNull { it.timestamp }?.let {
                    prefs.edit().putLong(KEY_LAST_EXIT_TS, it).apply()
                }
            } catch (e: Exception) {
                Log.w(TAG, "[WARN] Не удалось прочитать причины завершения: ${e.message}")
            }
        }
        for (name in listOf(CRASH_FILE)) {
            consumeFile(File(app.filesDir, name), "Сбой приложения")
        }
        consumeFile(File(app.cacheDir, PANIC_FILE), "Сбой движка")
    }

    private fun consumeFile(file: File, title: String) {
        if (!file.exists()) return
        try {
            val text = file.readText().trim()
            if (text.isNotEmpty()) {
                val lines = text.lines().take(12)
                Log.e(TAG, "[ERROR] $title при прошлом запуске: ${lines.first()}")
                lines.drop(1).forEach { Log.e(TAG, "[ERROR]   $it") }
                File(file.parentFile, file.name + ".old").writeText(text)
            }
        } catch (_: Exception) {
        } finally {
            runCatching { file.delete() }
        }
    }

    /** Текст последних сбоев для отчёта (сохраняется после показа в логах). */
    fun lastCrashes(context: Context): List<String> {
        val app = context.applicationContext
        return listOf(
            File(app.filesDir, "$CRASH_FILE.old"),
            File(app.cacheDir, "$PANIC_FILE.old")
        ).filter { it.exists() }.mapNotNull {
            runCatching { it.readText().lines().take(3).joinToString(" | ") }.getOrNull()
        }
    }
}

class ProxyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Diagnostics.installCrashHandler(this)
    }
}
