package com.bdfr.sentinel

import android.app.Activity
import android.content.Context
import android.content.res.Configuration
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import java.io.ByteArrayOutputStream
import java.util.Locale

private const val MAX_SCAN_BYTES = 32 * 1024 * 1024

private data class AppLanguage(val code: String, val label: String)

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var scanButton: Button
    private lateinit var title: TextView
    private var languageCode = "en"
    private var themeName = "Soban Default"
    private val nativeScanner by lazy { NativeScanner() }

    private val languages = listOf(
        AppLanguage("en", "English"), AppLanguage("fa", "فارسی"),
        AppLanguage("bal", "Balochi"), AppLanguage("ckb", "کوردی (سۆرانی)"),
        AppLanguage("ar", "العربية"), AppLanguage("de", "Deutsch"),
        AppLanguage("fr", "Français"), AppLanguage("es", "Español")
    )

    private val openDocument = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) {
            status.text = tr("no_file")
            return@registerForActivityResult
        }
        scanSelectedDocument(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = getSharedPreferences("soban-ui", Context.MODE_PRIVATE)
        languageCode = prefs.getString("language", "en") ?: "en"
        themeName = prefs.getString("theme", "Soban Default") ?: "Soban Default"

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(32, 40, 32, 32)
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        title = TextView(this).apply {
            text = "Soban"
            textSize = 30f
            gravity = Gravity.CENTER
        }
        val themePicker = Spinner(this)
        val themeNames = listOf("Soban Default", "Obsidian", "Arctic", "Graphite", "High Contrast")
        themePicker.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, themeNames)
        themePicker.setSelection(themeNames.indexOf(themeName).coerceAtLeast(0))
        themePicker.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) = Unit
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long) {
                themeName = themeNames[position]
                getSharedPreferences("soban-ui", Context.MODE_PRIVATE).edit().putString("theme", themeName).apply()
                applyTheme(root)
            }
        }
        val languagePicker = Spinner(this)
        languagePicker.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            languages.map { it.label }
        )
        languagePicker.setSelection(languages.indexOfFirst { it.code == languageCode }.coerceAtLeast(0))
        languagePicker.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) = Unit
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long) {
                val selected = languages[position].code
                if (selected != languageCode) {
                    languageCode = selected
                    getSharedPreferences("soban-ui", Context.MODE_PRIVATE).edit()
                        .putString("language", languageCode).apply()
                    applyLocaleDirection()
                    updateLabels()
                }
            }
        }

        status = TextView(this).apply {
            textSize = 17f
            gravity = Gravity.CENTER
            setPadding(0, 28, 0, 28)
        }
        scanButton = Button(this).apply {
            textSize = 16f
            setPadding(18, 12, 18, 12)
            isEnabled = NativeScanner.isAvailable
            setOnClickListener { openDocument.launch(arrayOf("*/*")) }
        }

        root.addView(title)
        root.addView(themePicker)
        root.addView(languagePicker)
        root.addView(status)
        root.addView(scanButton)
        setContentView(root)
        applyLocaleDirection()
        applyTheme(root)
        updateLabels()
    }

    private fun applyTheme(root: LinearLayout) {
        val palette = when (themeName) {
            "Obsidian" -> intArrayOf(0xFF090D15.toInt(), 0xFF172438.toInt(), 0xFF55A9FF.toInt(), 0xFFE8F2FF.toInt())
            "Arctic" -> intArrayOf(0xFFEAF5FA.toInt(), 0xFFD5EAF4.toInt(), 0xFF0878B8.toInt(), 0xFF18394B.toInt())
            "Graphite" -> intArrayOf(0xFF202326.toInt(), 0xFF343A40.toInt(), 0xFFB7C1CB.toInt(), 0xFFF1F3F5.toInt())
            "High Contrast" -> intArrayOf(0xFF000000.toInt(), 0xFF202020.toInt(), 0xFF00E5FF.toInt(), 0xFFFFFFFF.toInt())
            else -> intArrayOf(0xFF101B27.toInt(), 0xFF1D2B3A.toInt(), 0xFF60CDFF.toInt(), 0xFFF4F7FA.toInt())
        }
        root.setBackgroundColor(palette[0])
        title.setTextColor(palette[2])
        status.setTextColor(palette[3])
        scanButton.setTextColor(palette[3])
        scanButton.backgroundTintList = android.content.res.ColorStateList.valueOf(palette[1])
        title.text = when (themeName) {
            "Obsidian" -> "◉  Soban"
            "Arctic" -> "❖  Soban"
            "Graphite" -> "⬡  Soban"
            "High Contrast" -> "◆  SOBAN"
            else -> "⬡  Soban"
        }
    }

    private fun applyLocaleDirection() {
        val rtl = languageCode in setOf("fa", "ckb", "ar")
        window.decorView.layoutDirection = if (rtl) View.LAYOUT_DIRECTION_RTL else View.LAYOUT_DIRECTION_LTR
        val localeTag = when (languageCode) {
            "bal" -> "bal"
            "ckb" -> "ckb"
            else -> languageCode
        }
        @Suppress("DEPRECATION")
        resources.configuration.setLocale(Locale.forLanguageTag(localeTag))
    }

    private fun tr(key: String): String {
        val values = mapOf(
            "en" to mapOf("ready" to "Ready to scan files selected by you. Android limits access to files you grant.", "unavailable" to "Native scan engine is not installed. Protection is not active.", "choose" to "Choose a file to scan", "no_file" to "No file selected", "reading" to "Reading selected file…"),
            "fa" to mapOf("ready" to "آماده اسکن فایل‌هایی هستیم که شما انتخاب می‌کنید. دسترسی اندروید محدود به فایل‌های مجاز شماست.", "unavailable" to "موتور اسکن نصب نشده است؛ حفاظت فعال نیست.", "choose" to "انتخاب فایل برای اسکن", "no_file" to "فایلی انتخاب نشد", "reading" to "در حال خواندن فایل…"),
            "bal" to mapOf("ready" to "شما چه فایلے چُنّیت، آںءَ اسکین کنگءَ تیار اِنت. اندروئید فقط اجازت داتگیں فایلانءَ دسترس دنت.", "unavailable" to "اسکینر انجن نصب نہ اِنت؛ حفاظت فعال نہ اِنت.", "choose" to "اسکینءَ فایل چُنّیت", "no_file" to "هیچ فایلے چُنّگ نہ بوت", "reading" to "فایل خوانگءَ اِنت…"),
            "ckb" to mapOf("ready" to "ئامادەین بۆ پشکنینی ئەو فایلانەی کە خۆت هەڵیان دەبژێریت. دەستگەیشتن تەنها بە فایلە ڕێگەپێدراوەکانە.", "unavailable" to "مۆتۆری پشکنین دانەمەزراوە؛ پاراستن چالاک نییە.", "choose" to "فایلێک بۆ پشکنین هەڵبژێرە", "no_file" to "هیچ فایلێک هەڵنەبژێردرا", "reading" to "فایلەکە دەخوێندرێتەوە…"),
            "ar" to mapOf("ready" to "جاهز لفحص الملفات التي تختارها. يقتصر وصول أندرويد على الملفات التي تسمح بها.", "unavailable" to "محرك الفحص غير مثبت؛ الحماية غير نشطة.", "choose" to "اختر ملفاً للفحص", "no_file" to "لم يتم اختيار ملف", "reading" to "جارٍ قراءة الملف…"),
            "de" to mapOf("ready" to "Bereit zum Scannen ausgewählter Dateien. Android beschränkt den Zugriff auf freigegebene Dateien.", "unavailable" to "Scan-Engine nicht installiert. Schutz ist nicht aktiv.", "choose" to "Datei zum Scannen auswählen", "no_file" to "Keine Datei ausgewählt", "reading" to "Datei wird gelesen…"),
            "fr" to mapOf("ready" to "Prêt à analyser les fichiers que vous sélectionnez. Android limite l’accès aux fichiers autorisés.", "unavailable" to "Moteur d’analyse non installé. Protection inactive.", "choose" to "Choisir un fichier à analyser", "no_file" to "Aucun fichier sélectionné", "reading" to "Lecture du fichier…"),
            "es" to mapOf("ready" to "Listo para analizar los archivos que selecciones. Android limita el acceso a los archivos autorizados.", "unavailable" to "El motor de análisis no está instalado. Protección inactiva.", "choose" to "Elegir archivo para analizar", "no_file" to "No se seleccionó ningún archivo", "reading" to "Leyendo archivo…")
        )
        return values[languageCode]?.get(key) ?: values["en"]!!.getValue(key)
    }

    private fun updateLabels() {
        title.text = "Soban"
        status.text = if (NativeScanner.isAvailable) tr("ready") else tr("unavailable")
        scanButton.text = tr("choose")
        scanButton.isEnabled = NativeScanner.isAvailable
    }

    private fun scanSelectedDocument(uri: Uri) {
        if (!NativeScanner.isAvailable) {
            status.text = tr("unavailable")
            return
        }
        status.text = tr("reading")
        Thread {
            val result = try {
                val bytes = readBounded(uri)
                val label = uri.lastPathSegment ?: "selected-document"
                nativeScanner.scanBytes(bytes, label, filesDir.absolutePath)
            } catch (error: Exception) {
                "Scan unavailable: " + (error.message ?: "File could not be read")
            }
            runOnUiThread { status.text = result }
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
