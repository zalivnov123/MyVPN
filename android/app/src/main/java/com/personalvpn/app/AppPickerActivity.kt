package com.personalvpn.app

import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.CheckedTextView
import android.widget.ListView
import androidx.activity.ComponentActivity

// AppPickerActivity: checkbox list of installed apps; checked apps bypass the VPN.
class AppPickerActivity : ComponentActivity() {

    private val prefs by lazy { getSharedPreferences("myvpn", Context.MODE_PRIVATE) }

    data class AppInfo(val label: String, val pkg: String, var excluded: Boolean)

    private var apps: List<AppInfo> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Приложения в обход VPN"

        val excluded = prefs.getStringSet("excluded_apps", emptySet()) ?: emptySet()

        val pm = packageManager
        apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .filter { pm.getLaunchIntentForPackage(it.packageName) != null && it.packageName != packageName }
            .map { AppInfo(it.loadLabel(pm).toString(), it.packageName, excluded.contains(it.packageName)) }
            .sortedBy { it.label.lowercase() }

        val listView = ListView(this)
        val adapter = object : ArrayAdapter<AppInfo>(this, android.R.layout.simple_list_item_multiple_choice, apps) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val view = super.getView(position, convertView, parent) as CheckedTextView
                val app = apps[position]
                view.text = "${app.label}\n${app.pkg}"
                view.isChecked = app.excluded
                return view
            }
        }
        listView.adapter = adapter
        listView.choiceMode = ListView.CHOICE_MODE_MULTIPLE
        listView.setOnItemClickListener { _, _, position, _ ->
            val app = apps[position]
            app.excluded = !app.excluded
            adapter.notifyDataSetChanged()
        }
        setContentView(listView)
    }

    override fun onPause() {
        super.onPause()
        val selected = apps.filter { it.excluded }.map { it.pkg }.toSet()
        prefs.edit().putStringSet("excluded_apps", selected).apply()
    }
}
