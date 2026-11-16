package com.bdfr.sentinel

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts

/** Android shell. No clean verdict is possible until the Rust/JNI scanner is linked. */
class MainActivity : Activity() {
    private lateinit var status: TextView

    private val openDocument = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) {
            status.text = "No file selected"
            return@registerForActivityResult
        }
        status.text = "File selected: " + (uri.lastPathSegment ?: "document") +
            "\nNative scanner integration is pending. No clean verdict is assumed."
        try {
            contentResolver.takePersistableUriPermission(
                uri, Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } catch (_: SecurityException) {
            // Some providers grant only temporary access; keep the session usable.
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(32, 48, 32, 32)
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }
        val title = TextView(this).apply {
            text = "BDFR Sentinel"
            textSize = 28f
            gravity = Gravity.CENTER
        }
        status = TextView(this).apply {
            text = "Android protection is not active yet.\nRust scanner integration is pending."
            textSize = 16f
            gravity = Gravity.CENTER
            setPadding(0, 32, 0, 32)
        }
        val scan = Button(this).apply {
            text = "Choose a file to scan"
            setOnClickListener { openDocument.launch(arrayOf("*/*")) }
        }
        root.addView(title)
        root.addView(status)
        root.addView(scan)
        setContentView(root)
    }
}
