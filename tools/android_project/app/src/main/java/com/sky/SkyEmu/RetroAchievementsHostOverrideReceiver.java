package com.sky.SkyEmu;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class RetroAchievementsHostOverrideReceiver extends BroadcastReceiver {
    private static final String TAG = "SkyEmu";
    private static final String ACTION_SET_HOST_OVERRIDE_SUFFIX = ".action.SET_RETROACHIEVEMENTS_HOST_OVERRIDE";
    private static final String ACTION_CLEAR_HOST_OVERRIDE_SUFFIX = ".action.CLEAR_RETROACHIEVEMENTS_HOST_OVERRIDE";
    public static final String EXTRA_HOST = "host";
    // Read by se_apply_ra_host_override() in main.c; se_get_pref_path() is the files dir path without a trailing slash.
    private static final String HOST_OVERRIDE_FILE = "ra_host_override.txt";

    @Override
    public void onReceive(Context context, Intent intent) {
        String packageName = context.getPackageName();
        String action = intent.getAction();
        File file = new File(context.getFilesDir().getAbsolutePath() + HOST_OVERRIDE_FILE);

        if ((packageName + ACTION_SET_HOST_OVERRIDE_SUFFIX).equals(action)) {
            String host = normalize(intent.getStringExtra(EXTRA_HOST));
            if (host == null || !write(file, host)) {
                Log.w(TAG, "Rejected RetroAchievements host override");
                setResultCode(Activity.RESULT_CANCELED);
                return;
            }
            Log.i(TAG, "RetroAchievements host override set to " + host);
        } else if ((packageName + ACTION_CLEAR_HOST_OVERRIDE_SUFFIX).equals(action)) {
            if (file.exists() && !file.delete()) {
                setResultCode(Activity.RESULT_CANCELED);
                return;
            }
            Log.i(TAG, "RetroAchievements host override cleared");
        }
    }

    private static boolean write(File file, String host) {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(host.getBytes(StandardCharsets.UTF_8));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    static String normalize(String value) {
        String trimmed = value == null ? "" : value.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String candidate = trimmed.contains("://") ? trimmed : "http://" + trimmed;

        URI uri;
        try {
            uri = new URI(candidate);
        } catch (Exception e) {
            return null;
        }
        String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.US);
        String host = uri.getHost() == null ? null : uri.getHost().toLowerCase(Locale.US);
        String path = uri.getRawPath();

        if (!"http".equals(scheme)) {
            return null;
        }
        if (!"127.0.0.1".equals(host) && !"localhost".equals(host)) {
            return null;
        }
        if (uri.getPort() < 1 || uri.getPort() > 65535) {
            return null;
        }
        if (path != null && !path.isEmpty() && !path.equals("/") && !path.equals("/dorequest.php")) {
            return null;
        }
        if (uri.getRawQuery() != null || uri.getRawFragment() != null || uri.getRawUserInfo() != null) {
            return null;
        }
        return scheme + "://" + host + ":" + uri.getPort();
    }
}
