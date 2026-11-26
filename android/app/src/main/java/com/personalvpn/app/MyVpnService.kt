package com.personalvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import mobilelib.Mobilelib
import java.io.File

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
    private val handler = Handler(Looper.getMainLooper())
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
        Thread { connectAndRun() }.start()
        return START_STICKY
    }

    private fun connectAndRun() {
        try {
            if (!configFile.exists()) {
                Log.e("MyVPN", "no config.json")
                stopVpn()
                return
            }
            val configJSON = configFile.readText()
            val cidr = Mobilelib.connect(configJSON)  // throws on error
            tunnelIp = cidr
            val addr = cidr.substringBefore('/')
            val prefix = cidr.substringAfter('/', "24").toIntOrNull() ?: 24

            val builder = Builder()
                .setSession("MyVPN")
                .addAddress(addr, prefix)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .setMtu(1500)
                .setBlocking(true)

            // Per-app bypass: selected apps go direct (marketplaces, banks).
            val excluded = getSharedPreferences("myvpn", Context.MODE_PRIVATE)
                .getStringSet("excluded_apps", emptySet()) ?: emptySet()
            for (pkg in excluded) {
                try {
                    builder.addDisallowedApplication(pkg)
                    Log.i("MyVPN", "app bypass: $pkg")
                } catch (e: Exception) {
                    Log.w("MyVPN", "cannot bypass $pkg: ${e.message}")
                }
            }

            vpnInterface?.close()
            vpnInterface = builder.establish()
            val pfd = vpnInterface
            if (pfd == null) {
                Log.e("MyVPN", "establish() failed")
                stopVpn()
                return
            }
            running = true
            VpnEvents.activityListener?.invoke("running", null)
            Mobilelib.startPump(pfd.detachFd().toLong())
        } catch (e: Exception) {
            Log.e("MyVPN", "connect failed", e)
            VpnEvents.activityListener?.invoke("log", "connect failed: ${e.message}")
            if (shouldRun) {
                handler.postDelayed({ Thread { connectAndRun() }.start() }, 5000)
            } else {
                stopVpn()
            }
        }
    }

    private fun onState(state: String) {
        if (state == "lost" && shouldRun) {
            running = false
            handler.postDelayed({ Thread { connectAndRun() }.start() }, 3000)
        }
    }

    private fun stopVpn() {
        shouldRun = false
        running = false
        tunnelIp = ""
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
