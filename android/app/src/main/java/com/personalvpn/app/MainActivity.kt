package com.personalvpn.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.ScrollView
import android.widget.TextView
import android.widget.LinearLayout
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import java.io.File

class MainActivity : ComponentActivity() {

    private lateinit var statusText: TextView
    private lateinit var logText: TextView
    private lateinit var toggleBtn: Button

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) startVpn() else toast("VPN: нет разрешения")
    }

    private val filePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@registerForActivityResult
        try {
            contentResolver.openInputStream(uri)?.use { input ->
                File(filesDir, "config.json").writeBytes(input.readBytes())
            }
            toast("Конфиг импортирован")
            refresh()
        } catch (e: Exception) {
            toast("Ошибка импорта: ${e.message}")
        }
    }

    private val qrScanner = registerForActivityResult(ScanContract()) { result ->
        val content = result.contents ?: return@registerForActivityResult
        try {
            // Validate it's a JSON config
            org.json.JSONObject(content)
            File(filesDir, "config.json").writeText(content)
            toast("Конфиг импортирован из QR")
            refresh()
        } catch (e: Exception) {
            toast("QR не похож на конфиг")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 32, 32, 32) }
        toggleBtn = Button(this)
        statusText = TextView(this).apply { textSize = 16f; setPadding(0, 16, 0, 16) }
        val importFileBtn = Button(this).apply { text = "Импорт конфига (файл)" }
        val importQrBtn = Button(this).apply { text = "Импорт конфига (QR)" }
        val appPickerBtn = Button(this).apply { text = "Приложения в обход VPN" }
        logText = TextView(this).apply { textSize = 12f; typeface = android.graphics.Typeface.MONOSPACE }
        val scroll = ScrollView(this).apply { addView(logText) }

        root.addView(toggleBtn)
        root.addView(statusText)
        root.addView(importQrBtn)
        root.addView(importFileBtn)
        root.addView(appPickerBtn)
        root.addView(scroll, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)

        toggleBtn.setOnClickListener { onToggle() }
        importFileBtn.setOnClickListener { filePicker.launch(arrayOf("*/*")) }
        importQrBtn.setOnClickListener {
            qrScanner.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false).setPrompt("Наведите на QR-код с конфигом"))
        }
        appPickerBtn.setOnClickListener {
            startActivity(Intent(this, AppPickerActivity::class.java))
        }

        VpnEvents.activityListener = { state, msg -> runOnUiThread { refresh(); if (msg != null) appendLog(msg) } }
        refresh()
    }

    override fun onDestroy() {
        VpnEvents.activityListener = null
        super.onDestroy()
    }

    private fun onToggle() {
        if (MyVpnService.running) {
            MyVpnService.requestStop(this)
        } else {
            if (!File(filesDir, "config.json").exists()) {
                toast("Сначала импортируйте конфиг (файл или QR)")
                return
            }
            val intent = VpnService.prepare(this)
            if (intent != null) vpnConsent.launch(intent) else startVpn()
        }
    }

    private fun startVpn() {
        startForegroundService(Intent(this, MyVpnService::class.java))
        toggleBtn.text = "Подключаюсь..."
        statusText.text = "Статус: подключаюсь к серверу...\n(при недоступной сети будут повторные попытки)"
    }

    private fun refresh() {
        val running = MyVpnService.running
        toggleBtn.text = if (running) "Выключить" else "Запустить"
        val hasConfig = File(filesDir, "config.json").exists()
        statusText.text = buildString {
            append("Статус: ").append(if (running) "РАБОТАЕТ" else "выключен").append('\n')
            append("Конфиг: ").append(if (hasConfig) "загружен" else "НЕТ (импортируйте)").append('\n')
            append("Туннельный IP: ").append(MyVpnService.tunnelIp.ifEmpty { "-" })
        }
    }

    private fun appendLog(msg: String) {
        logText.append(msg + "\n")
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
}
