
package com.sky.SkyEmu.utils

import android.content.SharedPreferences
import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.preference.PreferenceManager
import com.sky.SkyEmu.SkyEmuApplication
import com.sky.SkyEmu.models.Game
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.io.IOException

object GameUtils {
    const val KEY_GAMES = "Games"

    private lateinit var preferences: SharedPreferences

    fun getGames(): List<Game> {
        var games = mutableListOf<Game>()
        val context = SkyEmuApplication.appContext
        preferences = PreferenceManager.getDefaultSharedPreferences(context)
        val serializedGames = preferences.getStringSet(KEY_GAMES, emptySet()) ?: emptySet()
        games = serializedGames.map { Json.decodeFromString<Game>(it) }.toMutableList()
        return games.toList()
    }

    fun getGame(uri: Uri): Game {
        val filePath = uri.toString()

        val newGame = Game(
            FileUtil.getFilename(uri).replace(
                "[\\t\\n\\r]+".toRegex(),
                " "
            ),
            filePath.replace("\n", " "),
            uri.toString(),
            null,
            FileUtil.getFilename(Uri.parse(filePath))
        )

        return newGame
    }

    fun addGame(uri: Uri) : LoaderResult {
        if (!isSupportedExtension(SkyEmuApplication.appContext, uri)) {
            return LoaderResult.Error
        }
        preferences = PreferenceManager.getDefaultSharedPreferences(SkyEmuApplication.appContext)
        val serializedGames = preferences.getStringSet(KEY_GAMES, emptySet()) ?: emptySet()
        val games = serializedGames.map { Json.decodeFromString<Game>(it) }.toMutableList()
        games.add(getGame(uri))
        val newSerializedGames = mutableSetOf<String>()
        games.forEach { newSerializedGames.add(Json.encodeToString(it)) }

        preferences.edit()
            .remove(KEY_GAMES)
            .putStringSet(KEY_GAMES, newSerializedGames)
            .apply()

        return LoaderResult.Success
     }

     private fun isSupportedExtension(context: Context, uri: Uri): Boolean {
        val contentResolver: ContentResolver = context.contentResolver
        val cursor = contentResolver.query(uri, null, null, null, null)

        cursor?.use {
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameIndex != -1 && cursor.moveToFirst()) {
                val fileName = cursor.getString(nameIndex) ?: return false
                val fileExtension = fileName.substringAfterLast('.', "").lowercase()
                return fileExtension in Game.supportedExtensions
           }
        }
        return false
    }
}

enum class LoaderResult(val code: Int) {
    Success(0),
    Error(1);
}
