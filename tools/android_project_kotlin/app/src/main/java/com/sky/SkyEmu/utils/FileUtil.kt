
package com.sky.SkyEmu.utils

import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.util.Log
import android.provider.DocumentsContract
import android.system.Os
import android.util.Pair
import androidx.documentfile.provider.DocumentFile
import com.sky.SkyEmu.SkyEmuApplication
import java.io.BufferedInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

object FileUtil {
    val context: Context get() = SkyEmuApplication.appContext


    /**
     * Check whether given path exists.
     *
     * @param path Native content uri path
     * @return bool
     */
    @JvmStatic
    fun exists(path: String): Boolean {
        var c: Cursor? = null
        try {
            val uri = Uri.parse(path)
            val columns = arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            c = context.contentResolver.query(
                uri,
                columns,
                null,
                null,
                null
            )
            return c!!.count > 0
        } catch (e: Exception) {
            Log.i("FileUtil", "Cannot find file from given path, error: " + e.message)
        } finally {
            // do nothing
        }
        return false
    }

    /**
     * Check whether given path is a directory
     *
     * @param path content uri path
     * @return bool
     */
    @JvmStatic
    fun isDirectory(path: String): Boolean {
        val columns = arrayOf(DocumentsContract.Document.COLUMN_MIME_TYPE)
        var isDirectory = false
        var c: Cursor? = null
        try {
            val uri = Uri.parse(path)
            c = context.contentResolver.query(uri, columns, null, null, null)
            c!!.moveToNext()
            val mimeType = c.getString(0)
            isDirectory = mimeType == DocumentsContract.Document.MIME_TYPE_DIR
        } catch (e: Exception) {
            Log.e("FileUtil", "Cannot list files, error: " + e.message)
        } finally {
            // do nothing 
        }
        return isDirectory
    }

    /**
     * Get file display name from given path
     *
     * @param uri content uri
     * @return String display name
     */
    @JvmStatic
    fun getFilename(uri: Uri): String {
        val columns = arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
        var filename = ""
        var c: Cursor? = null
        try {
            c = context.contentResolver.query(
                uri,
                columns,
                null,
                null,
                null
            )
            c!!.moveToNext()
            filename = c.getString(0)
        } catch (e: Exception) {
            Log.error("FileUtil", "Cannot get file name, error: " + e.message)
        } finally {
            // do nothing 
        }
        return filename
    }

    /**
     * Get file size from given path.
     *
     * @param path content uri path
     * @return long file size
     */
    @JvmStatic
    fun getFileSize(path: String): Long {
        val columns = arrayOf(DocumentsContract.Document.COLUMN_SIZE)
        var size: Long = 0
        var c: Cursor? = null
        try {
            val uri = Uri.parse(path)
            c = context.contentResolver.query(
                uri,
                columns,
                null,
                null,
                null
            )
            c!!.moveToNext()
            size = c.getLong(0)
        } catch (e: Exception) {
            Log.error("FileUtil", "Cannot get file size, error: " + e.message)
        } finally {
            // do nothing 
        }
        return size
    }
}
