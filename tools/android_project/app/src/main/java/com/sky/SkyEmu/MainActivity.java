package com.sky.SkyEmu;

import android.app.Activity;
import android.content.Intent;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(android.os.Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = new Intent(this, EnhancedNativeActivity.class);
        startActivity(intent);
    }
}