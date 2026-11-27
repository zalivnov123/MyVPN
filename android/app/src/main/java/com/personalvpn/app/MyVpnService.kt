package com.personalvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import mobilelib.Mobilelib
import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

// Callback hub: Go code posts here, service/activity subscribe.
object VpnEvents {
    var activityListener: ((state: String, msg: String?) -> Unit)? = null
    var serviceListener: ((state: String) -> Unit)? = null
}

class MyVpnService : VpnService() {

    companion object {
        @Volatile var running = false
            private set
        @Volatile var tunnelIp = ""
            private set
        @Volatile var shouldRun = false

        fun requestStop(context: Context) {
            shouldRun = false
            context.startService(Intent(context, MyVpnService::class.java).setAction("stop"))
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var workerThread: Thread? = null
    private val lostLatch = AtomicReference(CountDownLatch(1))
    private val configFile by lazy { File(filesDir, "config.json") }

    private inner class Protector : mobilelib.Protector {
        override fun protect(fd: Int): Boolean = this@MyVpnService.protect(fd)
    }

    private inner class EventSink : mobilelib.Events {
        override fun onLog(msg: String) {
            Log.i("MyVPN", msg)
            VpnEvents.activityListener?.invoke("log", msg)
        }
        override fun onStateChange(state: String) {
            VpnEvents.activityListener?.invoke(state, null)
            VpnEvents.serviceListener?.invoke(state)
        }
    }

    override fun onCreate() {
        super.onCreate()
        Mobilelib.setProtector(Protector())
        Mobilelib.setEvents(EventSink())
        VpnEvents.serviceListener = { state -> onState(state) }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "stop") {
            stopVpn()
            return START_NOT_STICKY
        }
        shouldRun = true
        startForegroundWithNotification()
        if (workerThread?.isAlive != true) {
            Log.i("MyVPN", "starting worker thread")
            lostLatch.set(CountDownLatch(1))
            workerThread = Thread({ workerLoop() }, "vpn-worker")
            workerThread?.start()
        } else {
            Log.i("MyVPN", "worker already alive")
        }
        return START_STICKY
    }

    // Single worker thread: connect -> establish -> pump -> wait for loss -> retry.
    // No competing reconnect paths (fixes wedged states after sleep/network loss).
    private fun workerLoop() {
        while (shouldRun) {
            try {
                Log.i("MyVPN", "worker: connecting...")
                if (!configFile.exists()) {
                    Log.e("MyVPN", "no config.json")
                    break
                }
                val configText = configFile.readText()
                val cidr = Mobilelib.connect(configText) // throws on error
                Log.i("MyVPN", "worker: connected, $cidr")
                tunnelIp = cidr
                val addr = cidr.substringBefore('/')
                val prefix = cidr.substringAfter('/', "24").toIntOrNull() ?: 24

                val builder = Builder()
                    .setSession("MyVPN")
                    .addAddress(addr, prefix)
                    .addDnsServer("1.1.1.1")
                    .setMtu(1500)
                    .setBlocking(true)

                // Per-app bypass (marketplaces, banks).
                val excludedApps = getSharedPreferences("myvpn", Context.MODE_PRIVATE)
                    .getStringSet("excluded_apps", emptySet()) ?: emptySet()
                for (pkg in excludedApps) {
                    try {
                        builder.addDisallowedApplication(pkg)
                        Log.i("MyVPN", "app bypass: $pkg")
                    } catch (e: Exception) {
                        Log.w("MyVPN", "cannot bypass $pkg")
                    }
                }

                // Domain bypass (e.g. ozon.ru): route everything EXCEPT these IPs.
                val excludedIps = resolveBypassDomains(configText)
                for ((ip, len) in complementRoutes(excludedIps)) {
                    builder.addRoute(ip, len)
                }

                vpnInterface?.close()
                val pfd = builder.establish()
                if (pfd == null) {
                    Log.e("MyVPN", "establish() failed")
                    Thread.sleep(5000)
                    continue
                }
                vpnInterface = pfd
                running = true
                VpnEvents.activityListener?.invoke("running", null)
                Log.i("MyVPN", "tunnel up: $cidr")

                Mobilelib.startPump(pfd.detachFd().toLong())

                // Wait until the session is lost (or stop requested).
                lostLatch.get().await()
                if (shouldRun) {
                    lostLatch.set(CountDownLatch(1))
                    running = false
                    VpnEvents.activityListener?.invoke("lost", null)
                }
            } catch (e: Exception) {
                Log.e("MyVPN", "worker error", e)
                VpnEvents.activityListener?.invoke("log", "connect failed: ${e.message}")
            }
            if (shouldRun) {
                running = false
                Thread.sleep(3000)
            }
        }
        Log.i("MyVPN", "worker stopped")
    }

    private fun resolveBypassDomains(configText: String): List<Pair<String, Int>> {
        val out = mutableListOf<Pair<String, Int>>()
        try {
            val cfg = JSONObject(configText)
            val arr = cfg.optJSONArray("bypass_domains") ?: return out
            for (i in 0 until arr.length()) {
                val domain = arr.getString(i)
                try {
                    for (addr in InetAddress.getAllByName(domain)) {
                        if (addr is java.net.Inet4Address) {
                            out.add(addr.hostAddress!! to 32)
                        }
                    }
                    Log.i("MyVPN", "bypass domain $domain: direct")
                } catch (e: Exception) {
                    Log.w("MyVPN", "bypass domain $domain: resolve failed")
                }
            }
        } catch (e: Exception) {
            Log.w("MyVPN", "bypass_domains parse: ${e.message}")
        }
        return out
    }

    // complementRoutes returns the route set covering 0.0.0.0/0 minus excluded prefixes.
    private fun complementRoutes(excluded: List<Pair<String, Int>>): List<Pair<String, Int>> {
        var result = mutableListOf("0.0.0.0" to 0)
        for (ex in excluded) {
            val next = mutableListOf<Pair<String, Int>>()
            for (cur in result) next.addAll(subtract(cur.first, cur.second, ex.first, ex.second))
            result = next
        }
        return result
    }

    private fun ipToLong(ip: String): Long =
        ip.split('.').fold(0L) { acc, part -> (acc shl 8) + part.toLong() }

    private fun longToIp(v: Long): String =
        "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"

    private fun subtract(ip: String, len: Int, exIp: String, exLen: Int): List<Pair<String, Int>> {
        val ipL = ipToLong(ip)
        val exL = ipToLong(exIp)
        val mask = if (len == 0) 0L else (-1L shl (32 - len)) and 0xFFFFFFFFL
        val exMask = (-1L shl (32 - exLen)) and 0xFFFFFFFFL
        // excluded overlaps current prefix?
        if ((exL and mask) != ipL) return listOf(ip to len)
        // excluded fully covers current prefix?
        if (len >= exLen) {
            return if ((ipL and exMask) == exL) emptyList() else listOf(ip to len)
        }
        // partial overlap: split in half
        val halfLen = len + 1
        val halfSize = 1L shl (32 - halfLen)
        return subtract(ip, halfLen, exIp, exLen) + subtract(longToIp(ipL + halfSize), halfLen, exIp, exLen)
    }

    private fun onState(state: String) {
        if (state == "lost") {
            lostLatch.get().countDown()
        }
    }

    private fun stopVpn() {
        shouldRun = false
        running = false
        tunnelIp = ""
        lostLatch.get().countDown()
        try { Mobilelib.stop() } catch (_: Exception) {}
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        VpnEvents.activityListener?.invoke("stopped", null)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startForegroundWithNotification() {
        val channelId = "myvpn"
        val nm = getSystemService(NotificationManager::class.java)
        nm?.createNotificationChannel(NotificationChannel(channelId, "MyVPN", NotificationManager.IMPORTANCE_LOW))
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, channelId)
            .setContentTitle("MyVPN")
            .setContentText("VPN активен")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .build()
        startForeground(1, notification)
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }
}
