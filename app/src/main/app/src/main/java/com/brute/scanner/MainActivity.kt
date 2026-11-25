package com.brute.scanner

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.view.Gravity
import android.view.View
import android.widget.*
import java.security.MessageDigest

class MainActivity : Activity() {

    private val PICK_FILE = 1
    private val PICK_FOLDER = 2
    private val BG = Color.parseColor("#0D1117")
    private var onHome = true

    private val RISKY = setOf("apk", "exe", "scr", "bat", "cmd", "vbs", "js",
        "jar", "msi", "com", "pif", "ps1", "sh", "dex", "lnk", "hta")
    private val MAYBE = setOf("zip", "rar", "7z", "iso", "docm", "xlsm", "html", "htm")
    private val HARMLESS = setOf("jpg", "jpeg", "png", "gif", "pdf", "txt",
        "mp3", "mp4", "doc", "docx", "xls", "xlsx")

    class Result(val name: String, val score: Int, val notes: List<String>, val sha: String)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showHome()
    }

    override fun onBackPressed() {
        if (onHome) super.onBackPressed() else showHome()
    }

    // ---------- UI helpers ----------
    private fun page(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(48, 48, 48, 48)
    }

    private fun label(s: String, size: Float, color: Int = Color.WHITE, bold: Boolean = false) =
        TextView(this).apply {
            text = s
            textSize = size
            setTextColor(color)
            if (bold) setTypeface(null, Typeface.BOLD)
        }

    private fun btn(s: String, onClick: () -> Unit) = Button(this).apply {
        text = s
        textSize = 18f
        setTextColor(Color.WHITE)
        setBackgroundColor(Color.parseColor("#238636"))
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = 24 }
        setOnClickListener { onClick() }
    }

    private fun colorFor(score: Int) = when {
        score <= 3 -> Color.parseColor("#F85149")
        score <= 6 -> Color.parseColor("#D29922")
        else -> Color.parseColor("#3FB950")
    }

    private fun verdict(score: Int) = when {
        score <= 3 -> "DANGEROUS"
        score <= 6 -> "SUSPICIOUS"
        else -> "Looks clean (no guarantee)"
    }

    // ---------- Screens ----------
    private fun showHome() {
        onHome = true
        val l = page().apply { gravity = Gravity.CENTER; setBackgroundColor(BG) }
        l.addView(label("Brute Virus Scanner", 36f, Color.WHITE, true).apply { gravity = Gravity.CENTER })
        l.addView(View(this), LinearLayout.LayoutParams(1, 120))
        l.addView(btn("Scan File") {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }, PICK_FILE)
        })
        l.addView(btn("Scan Folder") {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), PICK_FOLDER)
        })
        setContentView(l)
    }

    private fun showMessage(m: String) {
        onHome = false
        val l = page().apply { gravity = Gravity.CENTER; setBackgroundColor(BG) }
        l.addView(label(m, 24f).apply { gravity = Gravity.CENTER })
        setContentView(l)
    }

    private fun showSingle(r: Result) {
        onHome = false
        val l = page().apply { setBackgroundColor(BG) }
        l.addView(label("${r.score}/10", 64f, colorFor(r.score), true).apply { gravity = Gravity.CENTER })
        l.addView(label(verdict(r.score), 22f, colorFor(r.score), true).apply { gravity = Gravity.CENTER })
        l.addView(label("\n" + r.name, 18f))
        if (r.sha.isNotEmpty()) l.addView(label("SHA-256:\n" + r.sha, 12f, Color.GRAY))
        val notes = if (r.notes.isEmpty()) "No red flags found."
        else r.notes.joinToString("\n") { "• $it" }
        l.addView(label("\n" + notes, 16f))
        l.addView(btn("Back") { showHome() })
        setContentView(ScrollView(this).apply { setBackgroundColor(BG); addView(l) })
    }

    private fun showFolder(all: List<Result>) {
        onHome = false
        val sorted = all.sortedBy { it.score }
        val low = sorted.firstOrNull()?.score ?: 10
        val l = page().apply { setBackgroundColor(BG) }
        l.addView(label("Folder scan", 28f, Color.WHITE, true))
        l.addView(label("${all.size} files scanned, lowest score: $low/10", 16f, colorFor(low)))
        for (r in sorted) {
            l.addView(label("\n${r.score}/10  ${r.name}", 16f, colorFor(r.score), true))
            for (n in r.notes) l.addView(label("   • $n", 13f, Color.LTGRAY))
        }
        l.addView(btn("Back") { showHome() })
        setContentView(ScrollView(this).apply { setBackgroundColor(BG); addView(l) })
    }

    // ---------- Picker result ----------
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        if (resultCode != RESULT_OK || uri == null) return
        showMessage("Scanning...")
        Thread {
            if (requestCode == PICK_FILE) {
                val r = scanUri(uri, nameOf(uri))
                runOnUiThread { showSingle(r) }
            } else {
                val files = ArrayList<Pair<Uri, String>>()
                walk(uri, DocumentsContract.getTreeDocumentId(uri), files, 0)
                val results = files.map { scanUri(it.first, it.second) }
                runOnUiThread { showFolder(results) }
            }
        }.start()
    }

    private fun nameOf(uri: Uri): String {
        contentResolver.query(uri, null, null, null, null)?.use { c ->
            val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (c.moveToFirst() && i >= 0) return c.getString(i)
        }
        return "unknown"
    }

    // ---------- Folder walking (max 300 files, 6 levels deep) ----------
    private fun walk(tree: Uri, docId: String, out: MutableList<Pair<Uri, String>>, depth: Int) {
        if (out.size >= 300 || depth > 6) return
        val kids = DocumentsContract.buildChildDocumentsUriUsingTree(tree, docId)
        val cols = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE
        )
        contentResolver.query(kids, cols, null, null, null)?.use { c ->
            while (c.moveToNext()) {
                val id = c.getString(0)
                val nm = c.getString(1)
                val mime = c.getString(2)
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                    walk(tree, id, out, depth + 1)
                } else {
                    out.add(Pair(DocumentsContract.buildDocumentUriUsingTree(tree, id), nm))
                }
                if (out.size >= 300) break
            }
        }
    }

    // ---------- The scanner ----------
    private fun scanUri(uri: Uri, name: String): Result {
        val notes = ArrayList<String>()
        var score = 10
        val parts = name.lowercase().split(".")
        val ext = if (parts.size > 1) parts.last() else ""
        val prev = if (parts.size > 2) parts[parts.size - 2] else ""

        val head = ByteArray(1024 * 1024)
        var read = 0
        var total = 0L
        val limit = 50L * 1024 * 1024
        val md = MessageDigest.getInstance("SHA-256")
        try {
            contentResolver.openInputStream(uri)?.use { s ->
                val buf = ByteArray(65536)
                while (total < limit) {
                    val n = s.read(buf)
                    if (n < 0) break
                    if (read < head.size) {
                        val c = minOf(n, head.size - read)
                        System.arraycopy(buf, 0, head, read, c)
                        read += c
                    }
                    md.update(buf, 0, n)
                    total += n
                }
            }
        } catch (e: Exception) {
            return Result(name, 5, listOf("Could not read this file"), "")
        }
        val sha = md.digest().joinToString("") { "%02x".format(it) }
        if (total >= limit) notes.add("Only the first 50 MB was scanned")

        val text = String(head, 0, read, Charsets.ISO_8859_1)
        if (text.contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
            notes.add("Matches the EICAR antivirus test signature")
            return Result(name, 1, notes, sha)
        }

        if (ext in RISKY) {
            score -= 3
            notes.add("Program/script type (.$ext) can run code")
        } else if (ext in MAYBE) {
            score -= 1
            notes.add("Archive/document type (.$ext) can hide other files")
        }
        if (ext in RISKY && prev in HARMLESS) {
            score -= 4
            notes.add("Double extension: looks like .$prev but is really .$ext")
        }
        if (read >= 2 && head[0] == 0x4D.toByte() && head[1] == 0x5A.toByte() &&
            ext !in setOf("exe", "dll", "scr", "com", "msi", "sys")) {
            score -= 5
            notes.add("Windows program disguised as .$ext")
        }
        if (read >= 4 && head[0] == 0x7F.toByte() && head[1] == 0x45.toByte() &&
            head[2] == 0x4C.toByte() && head[3] == 0x46.toByte() &&
            ext !in setOf("so", "elf", "bin", "o")) {
            score -= 3
            notes.add("Native executable disguised as .$ext")
        }
        if (text.startsWith("dex\n") && ext != "dex") {
            score -= 3
            notes.add("Android code file disguised as .$ext")
        }
        return Result(name, score.coerceIn(1, 10), notes, sha)
    }
}
