
package com.sky.SkyEmu.models

import android.content.Intent
import android.net.Uri
import android.os.Parcelable
import com.sky.SkyEmu.EmulationActivity
import kotlinx.parcelize.Parcelize
import kotlinx.serialization.Serializable
import java.util.HashSet

@Parcelize
@Serializable
class Game(
    val title: String = "",
    val description: String = "",
    val path: String = "",
    val icon: IntArray? = null,
    val filename: String
) : Parcelable {
    companion object {
        val supportedExtensions: Set<String> get() = extensions

        val extensions: Set<String> = HashSet(
            listOf("gb", "gba")
        )
    }
}