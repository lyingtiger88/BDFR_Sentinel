package com.bdfr.sentinel

import android.app.Activity
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import java.io.ByteArrayOutputStream

private const val MAX_SCAN_BYTES = 32 * 1024 * 1024

class MainActivity : Activity() {
    private lateinit var status: TextView
    private val nativeScanner by lazy { NativeScanner() }

    private val openDocument = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) {
            status.text = "No file selected"
            return@registerForActivityResult
        }
        scanSelectedDocument(uri)
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
            text = "Soban"
            textSize = 28f
            gravity = Gravity.CENTER
        }
        status = TextView(this).apply {
            text = if (NativeScanner.isAvailable) {
                "Ready for user-selected file scans.\nCoverage is limited to files Android grants access to."
            } else {
                "Native scan engine is not packaged yet.\nProtection is not active."
            }
            textSize = 16f
            gravity = Gravity.CENTER
            setPadding(0, 32, 0, 32)
        }
        val scan = Button(this).apply {
            text = "Choose a file to scan"
            isEnabled = NativeScanner.isAvailable
            setOnClickListener { openDocument.launch(arrayOf("*/*")) }
        }
        root.addView(title)
        root.addView(status)
        root.addView(scan)
        setContentView(root)
    }

    private fun scanSelectedDocument(uri: Uri) {
        if (!NativeScanner.isAvailable) {
            status.text = "Native scan engine is not installed. No clean verdict can be produced."
            return
        }

        status.text = "Reading selected file…"
        Thread {
            val result = try {
                val bytes = readBounded(uri)
                val label = uri.lastPathSegment ?: "selected-document"
                nativeScanner.scanBytes(bytes, label, filesDir.absolutePath)
            } catch (error: Exception) {
                "Scan unavailable: " + (error.message ?: "File could not be read")
            }
            runOnUiThread {
                status.text = result
            }
        }.start()
    }

    private fun readBounded(uri: Uri): ByteArray {
        val input = contentResolver.openInputStream(uri)
            ?: throw IllegalStateException("Android could not open the selected document")
        input.use { stream ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                total += count
                if (total > MAX_SCAN_BYTES) {
                    throw IllegalArgumentException("File exceeds the 32 MiB mobile scan limit")
                }
                output.write(buffer, 0, count)
            }
            return output.toByteArray()
        }
    }
}
