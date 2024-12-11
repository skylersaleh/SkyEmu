package com.sky.SkyEmu

import android.app.NativeActivity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.database.Cursor
import android.graphics.Rect
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.InputType
import android.util.DisplayMetrics
import android.util.Log
import android.view.*
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.FrameLayout
import androidx.browser.customtabs.CustomTabsIntent
import java.io.*
import java.util.Locale

class EmulationActivity : NativeActivity() {

    companion object {
        private const val APP_STORAGE_ACCESS_REQUEST_CODE = 501
        private const val STORAGE_PERMISSION_CODE = 501
        private const val FILE_PICKER_REQUEST_CODE = 123
        private const val TAG = "SkyEmu"

        init {
            System.loadLibrary("SkyEmu")
        }

        @JvmStatic
        fun getLanguage(): String = Locale.getDefault().toString()
    }

    private lateinit var visibleRect: Rect
    private var invisibleEditText: EditText? = null
    private lateinit var mRootView: View
    private val keyboardEvents = mutableListOf<Int>()
    private var firstEvent = true
    private lateinit var authIntent: CustomTabsIntent

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        firstEvent = true
        val mRootWindow = window
        mRootView = mRootWindow.decorView.findViewById(android.R.id.content)
        invisibleEditText = null

        mRootView.viewTreeObserver.addOnGlobalLayoutListener {
            val r = Rect()
            mRootWindow.decorView.getWindowVisibleDisplayFrame(r)
            visibleRect = r
        }

        val flags = (View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_FULLSCREEN
                or View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY)

        mRootWindow.decorView.setOnGenericMotionListener { _, event ->
            for (i in 0 until event.pointerCount) {
                event.device.motionRanges.forEach { range ->
                    val ax = range.axis
                    val v = event.getAxisValue(ax, i)
                    val intVal = (v * 32767).toInt()
                    val skyemuEvent = 0x10000000 or (ax shl 16) or (intVal and 0xffff)
                    keyboardEvents.add(skyemuEvent)
                }
            }
            false
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            window.decorView.systemUiVisibility = flags
            window.decorView.setOnSystemUiVisibilityChangeListener {
                if ((it and View.SYSTEM_UI_FLAG_FULLSCREEN) == 0) {
                    window.decorView.systemUiVisibility = flags
                }
            }
        }
    }

    fun getDPIScale(): Float {
        val metrics = resources.displayMetrics
        windowManager.defaultDisplay.getRealMetrics(metrics)
        return metrics.xdpi / 120.0f
    }

    fun requestPermissions() {}

    fun showKeyboard() {
        runOnUiThread {
            if (invisibleEditText == null) {
                val params = FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT
                )
                invisibleEditText = EditText(this).apply {
                    layoutParams = params
                    setRawInputType(InputType.TYPE_CLASS_TEXT)
                    imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI
                    setOnKeyListener { _, _, _ -> true }
                }
                (mRootView as FrameLayout).addView(invisibleEditText)
            }
            invisibleEditText?.requestFocus()
            (getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).showSoftInput(
                invisibleEditText,
                InputMethodManager.SHOW_IMPLICIT
            )
        }
    }

    fun hideKeyboard() {
        runOnUiThread {
            (mRootView as FrameLayout).removeView(invisibleEditText)
            invisibleEditText = null
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == STORAGE_PERMISSION_CODE && grantResults.isNotEmpty()) {
            val write = grantResults[0] == PackageManager.PERMISSION_GRANTED
            val read = grantResults[1] == PackageManager.PERMISSION_GRANTED
            Log.d(TAG, if (write && read) "Permissions granted" else "Permissions denied")
        }
    }

    fun openFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "*/*"
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        }
        startActivityForResult(intent, FILE_PICKER_REQUEST_CODE)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (resultCode != RESULT_OK) return
        if (requestCode == FILE_PICKER_REQUEST_CODE) {
            val selectedFileUri = data?.data ?: return
            loadURI(selectedFileUri, false)
        }
    }

    fun loadURI(selectedFileUri: Uri, isRom: Boolean) {
        val filename = getFileName(selectedFileUri)
        val externalDirPath = getExternalFilesDir(null)?.absolutePath ?: return
        val copiedFile = copyFileToExternalDirectory(selectedFileUri, externalDirPath, filename)
        copiedFile?.let {
            val copiedFilePath = it.absolutePath
            if (isRom) se_android_load_rom(copiedFilePath)
            se_android_load_file(copiedFilePath)
        }
    }

    private fun getFileName(uri: Uri): String {
        var result: String? = null
        if (uri.scheme == "content") {
            contentResolver.query(uri, null, null, null, null)?.use {
                if (it.moveToFirst()) {
                    result = it.getString(it.getColumnIndex(OpenableColumns.DISPLAY_NAME))
                }
            }
        }
        return result ?: uri.path?.substringAfterLast('/') ?: ""
    }

    private fun copyFileToExternalDirectory(
        sourceFilePath: Uri,
        destinationDirectoryPath: String,
        filename: String
    ): File? {
        val destinationDir = File(destinationDirectoryPath).apply { if (!exists()) mkdirs() }
        val copiedFile = File(destinationDir, filename)
        return try {
            contentResolver.openInputStream(sourceFilePath)?.use { input ->
                FileOutputStream(copiedFile).use { output ->
                    input.copyTo(output)
                }
            }
            copiedFile
        } catch (e: IOException) {
            e.printStackTrace()
            null
        }
    }

    external fun se_android_load_file(filePath: String)
    external fun se_android_load_rom(filePath: String)
}
