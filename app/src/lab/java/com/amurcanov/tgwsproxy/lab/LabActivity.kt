package com.amurcanov.tgwsproxy.lab

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.telephony.TelephonyManager
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Cancel
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import com.amurcanov.tgwsproxy.BuildConfig
import com.amurcanov.tgwsproxy.ui.AppSectionCard
import com.amurcanov.tgwsproxy.ui.TgWsProxyTheme
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Функции лаборатории из libtgwsproxy.so (src/lab.rs). */
interface LabLibrary : Library {
    companion object {
        val INSTANCE: LabLibrary by lazy {
            Native.load("tgwsproxy", LabLibrary::class.java) as LabLibrary
        }
    }

    fun LabStart(config: String): Int
    fun LabPoll(): Pointer?
    fun LabCancel()
    fun FreeString(p: Pointer)
}

data class LabItem(
    val group: String,
    val id: String,
    val title: String,
    val ok: Boolean,
    val ms: Long,
    val detail: String,
)

data class LabSnapshot(
    val running: Boolean = false,
    val total: Int = 0,
    val done: Int = 0,
    val durationMs: Long = 0,
    val startedUnix: Long = 0,
    val results: List<LabItem> = emptyList(),
    val summary: List<String> = emptyList(),
)

data class NetInfo(
    val kind: String,
    val operator: String,
    val vpn: Boolean,
    val privateDns: String,
) {
    fun title(): String = buildString {
        append(kind)
        if (operator.isNotBlank()) append(" · ").append(operator)
    }
}

object LabNative {
    fun start(config: JSONObject): Int = LabLibrary.INSTANCE.LabStart(config.toString())

    fun cancel() = LabLibrary.INSTANCE.LabCancel()

    fun poll(): LabSnapshot {
        val lib = LabLibrary.INSTANCE
        val p = lib.LabPoll() ?: return LabSnapshot()
        val json = try {
            p.getString(0, "UTF-8")
        } finally {
            lib.FreeString(p)
        }
        val o = JSONObject(json)
        val arr = o.optJSONArray("results")
        val items = buildList {
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    val r = arr.getJSONObject(i)
                    add(
                        LabItem(
                            group = r.optString("group"),
                            id = r.optString("id"),
                            title = r.optString("title"),
                            ok = r.optBoolean("ok"),
                            ms = r.optLong("ms"),
                            detail = r.optString("detail"),
                        )
                    )
                }
            }
        }
        val sum = o.optJSONArray("summary")
        return LabSnapshot(
            running = o.optBoolean("running"),
            total = o.optInt("total"),
            done = o.optInt("done"),
            durationMs = o.optLong("duration_ms"),
            startedUnix = o.optLong("started_unix"),
            results = items,
            summary = buildList {
                if (sum != null) for (i in 0 until sum.length()) add(sum.getString(i))
            },
        )
    }
}

private val GROUPS = listOf(
    "telegram" to "Telegram",
    "miniapps" to "Мини-приложения",
    "dns" to "DNS",
    "udp" to "UDP / звонки",
)

class LabActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContent {
            TgWsProxyTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    LabScreen(
                        keepScreenOn = { on ->
                            if (on) window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                            else window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                        }
                    )
                }
            }
        }
    }
}

private fun readNetInfo(context: Context): NetInfo {
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val net = cm.activeNetwork
    val caps = net?.let { cm.getNetworkCapabilities(it) }
    val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    val kind = when {
        caps == null -> "Нет сети"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Мобильная сеть"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
        vpn -> "VPN"
        else -> "Другая сеть"
    }
    val operator = if (kind == "Мобильная сеть") {
        runCatching {
            (context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager).networkOperatorName
        }.getOrDefault("")
    } else ""
    val privateDns = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        val lp = net?.let { cm.getLinkProperties(it) }
        when {
            lp == null -> ""
            lp.privateDnsServerName != null -> lp.privateDnsServerName!!
            lp.isPrivateDnsActive -> "автоматически"
            else -> "выключен"
        }
    } else ""
    return NetInfo(kind, operator, vpn, privateDns)
}

private fun buildReport(s: LabSnapshot, net: NetInfo, workerCount: Int, cfDomain: Boolean): String {
    val fmt = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.US)
    return buildString {
        appendLine("TgWsProxy — отчёт лаборатории")
        appendLine("Версия: ${BuildConfig.VERSION_NAME}, Android ${Build.VERSION.RELEASE}, ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine(
            "Сеть: ${net.title()}; VPN: ${if (net.vpn) "ВКЛЮЧЁН" else "нет"}" +
                (if (net.privateDns.isNotBlank()) "; Private DNS: ${net.privateDns}" else "")
        )
        if (s.startedUnix > 0) {
            appendLine("Время: ${fmt.format(Date(s.startedUnix * 1000))}, длительность ${s.durationMs / 1000} с")
        }
        appendLine("CF worker: ${if (workerCount > 0) "указан ($workerCount)" else "не указан"}; свой CF-домен: ${if (cfDomain) "да" else "нет"}")
        if (s.summary.isNotEmpty()) {
            appendLine()
            appendLine("Выводы:")
            s.summary.forEach { appendLine("  $it") }
        }
        for ((key, name) in GROUPS) {
            val items = s.results.filter { it.group == key }.sortedBy { it.id }
            if (items.isEmpty()) continue
            appendLine()
            appendLine("[$name]")
            items.forEach {
                appendLine("${if (it.ok) "✓" else "✗"} ${it.title} — ${it.ms} мс")
                appendLine("    ${it.detail}")
            }
        }
    }
}

@Composable
private fun LabScreen(keepScreenOn: (Boolean) -> Unit) {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("lab", Context.MODE_PRIVATE) }
    var workers by remember { mutableStateOf(prefs.getString("workers", "") ?: "") }
    var cfDomain by remember { mutableStateOf(prefs.getString("cf_domain", "") ?: "") }
    var snapshot by remember { mutableStateOf(LabSnapshot()) }
    var net by remember { mutableStateOf(readNetInfo(context)) }
    var polling by remember { mutableStateOf(false) }

    LaunchedEffect(polling) {
        if (!polling) return@LaunchedEffect
        keepScreenOn(true)
        while (true) {
            val s = withContext(Dispatchers.IO) { runCatching { LabNative.poll() }.getOrNull() }
            if (s != null) snapshot = s
            if (s == null || !s.running) break
            delay(400)
        }
        keepScreenOn(false)
        polling = false
    }
    DisposableEffect(Unit) {
        onDispose { keepScreenOn(false) }
    }

    fun start() {
        prefs.edit().putString("workers", workers.trim()).putString("cf_domain", cfDomain.trim()).apply()
        net = readNetInfo(context)
        val meta = JSONObject()
            .put("network", net.title())
            .put("vpn", net.vpn)
            .put("private_dns", net.privateDns)
            .put("version", BuildConfig.VERSION_NAME)
            .put("android", Build.VERSION.RELEASE)
            .put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
        val cfg = JSONObject()
            .put("worker_domains", workers.trim())
            .put("cf_domain", cfDomain.trim())
            .put("cache_dir", context.cacheDir.absolutePath)
            .put("meta", meta)
        val r = runCatching { LabNative.start(cfg) }.getOrElse { -2 }
        when (r) {
            0, 1 -> polling = true
            else -> Toast.makeText(context, "Не удалось запустить проверку ($r)", Toast.LENGTH_LONG).show()
        }
    }

    val workerCount = workers.split(',', '\n', ' ', ';').count { it.isNotBlank() }
    val report = { buildReport(snapshot, net, workerCount, cfDomain.isNotBlank()) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.systemBars),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            AppSectionCard(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Лаборатория соединений", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "Проверяет, какие пути до Telegram, мини-приложений и звонков работают в текущей сети. " +
                        "Запусти на Wi-Fi и на мобильном интернете и пришли оба отчёта. " +
                        "Основной прокси на время проверки лучше выключить.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text("Сеть: ${net.title()}", style = MaterialTheme.typography.titleSmall)
                if (net.vpn) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Rounded.Warning, null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(
                            "Включён VPN — результаты будут про VPN, а не про провайдера. Выключи его.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        }
        item {
            AppSectionCard(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = workers,
                    onValueChange = { workers = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("CF worker (необязательно)") },
                    placeholder = { Text("xxxx.user.workers.dev") },
                    enabled = !snapshot.running,
                    singleLine = false,
                    maxLines = 3,
                )
                OutlinedTextField(
                    value = cfDomain,
                    onValueChange = { cfDomain = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Свой CF-домен (необязательно)") },
                    enabled = !snapshot.running,
                    singleLine = true,
                )
                Text(
                    "Без worker проверка мини-приложений будет только напрямую. В отчёте домены сокращаются.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (snapshot.running) {
                    OutlinedButton(onClick = { LabNative.cancel() }, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Rounded.Stop, null)
                        Spacer(Modifier.width(8.dp))
                        Text("Остановить")
                    }
                    val progress = if (snapshot.total > 0) snapshot.done.toFloat() / snapshot.total else 0f
                    LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
                    Text("Готово ${snapshot.done} из ${snapshot.total}", style = MaterialTheme.typography.bodySmall)
                } else {
                    Button(onClick = { start() }, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Rounded.PlayArrow, null)
                        Spacer(Modifier.width(8.dp))
                        Text(if (snapshot.results.isEmpty()) "Начать проверку" else "Проверить ещё раз")
                    }
                }
            }
        }
        if (!snapshot.running && snapshot.results.isNotEmpty()) {
            item {
                AppSectionCard(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Выводы", style = MaterialTheme.typography.titleMedium)
                    if (snapshot.summary.isEmpty()) {
                        Text("Нет данных для выводов.", style = MaterialTheme.typography.bodyMedium)
                    }
                    snapshot.summary.forEach {
                        Text(it, style = MaterialTheme.typography.bodyMedium)
                    }
                    Text(
                        "Проверка заняла ${snapshot.durationMs / 1000} с",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(onClick = {
                            val send = Intent(Intent.ACTION_SEND)
                                .setType("text/plain")
                                .putExtra(Intent.EXTRA_SUBJECT, "Отчёт лаборатории TgWsProxy")
                                .putExtra(Intent.EXTRA_TEXT, report())
                            context.startActivity(Intent.createChooser(send, "Отправить отчёт"))
                        }) {
                            Icon(Icons.Rounded.Share, null)
                            Spacer(Modifier.width(6.dp))
                            Text("Поделиться")
                        }
                        OutlinedButton(onClick = {
                            val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            cb.setPrimaryClip(ClipData.newPlainText("lab", report()))
                            Toast.makeText(context, "Отчёт скопирован", Toast.LENGTH_SHORT).show()
                        }) {
                            Icon(Icons.Rounded.ContentCopy, null)
                            Spacer(Modifier.width(6.dp))
                            Text("Копировать")
                        }
                    }
                }
            }
        }
        for ((key, name) in GROUPS) {
            val groupItems = snapshot.results.filter { it.group == key }.sortedBy { it.id }
            if (groupItems.isEmpty()) continue
            item(key = "h_$key") {
                Text(
                    "$name · ${groupItems.count { it.ok }} из ${groupItems.size}",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(start = 4.dp, top = 4.dp),
                )
            }
            items(groupItems, key = { it.id }) { ResultRow(it) }
        }
    }
}

@Composable
private fun ResultRow(item: LabItem) {
    val okColor = Color(0xFF2E7D32)
    AppSectionCard(
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (item.ok) Icons.Rounded.CheckCircle else Icons.Rounded.Cancel,
                contentDescription = if (item.ok) "работает" else "не работает",
                tint = if (item.ok) okColor else MaterialTheme.colorScheme.error,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                item.title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f),
            )
            Text("${item.ms} мс", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Box(Modifier.padding(start = 28.dp)) {
            Text(item.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
