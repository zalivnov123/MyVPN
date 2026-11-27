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
        // Restore checked state through the ListView (it manages it in multiple-choice mode).
        apps.forEachIndexed { i, app -> listView.setItemChecked(i, app.excluded) }
        listView.setOnItemClickListener { _, _, position, _ ->
            val app = apps[position]
            app.excluded = !app.excluded
            listView.setItemChecked(position, app.excluded)
            adapter.notifyDataSetChanged()
            save() // сохраняем сразу при каждом клике
        }

        val root = android.widget.LinearLayout(this).apply { orientation = android.widget.LinearLayout.VERTICAL }
        val saveBtn = android.widget.Button(this).apply {
            text = "Сохранить (и перезапустите VPN)"
            setOnClickListener {
                save()
                android.widget.Toast.makeText(this@AppPickerActivity, "Сохранено. Перезапустите VPN.", android.widget.Toast.LENGTH_LONG).show()
                finish()
            }
        }
        root.addView(listView, android.widget.LinearLayout.LayoutParams(android.widget.LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        root.addView(saveBtn)
        setContentView(root)
    }

    private fun save() {
        val selected = apps.filter { it.excluded }.map { it.pkg }.toSet()
        prefs.edit().putStringSet("excluded_apps", selected).apply()
    }

    override fun onPause() {
        super.onPause()
        save()
    }
}
