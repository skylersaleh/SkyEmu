
package com.sky.SkyEmu

import android.annotation.SuppressLint
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build

class SkyEmuApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        applicationInstance = this
    }

    companion object {
        private var applicationInstance: SkyEmuApplication? = null

        val appContext: Context get() = applicationInstance!!.applicationContext
    }
}
