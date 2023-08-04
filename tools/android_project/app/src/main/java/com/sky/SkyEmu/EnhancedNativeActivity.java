package com.sky.SkyEmu;

import static android.provider.Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION;
import static android.view.KeyEvent.*;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.text.InputType;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;

import android.app.NativeActivity;
import android.widget.EditText;
import android.widget.FrameLayout;

import java.io.File;
import java.util.Locale;
import java.util.Vector;

public class EnhancedNativeActivity extends NativeActivity {
    final static int APP_STORAGE_ACCESS_REQUEST_CODE = 501; // Any value
    final static int STORAGE_PERMISSION_CODE = 501; // Any value
    final static String TAG="SkyEmu"; // Any value
    public Rect visibleRect;
    public EditText invisibleEditText;
    private Vector<Integer> keyboardEvents;
    public void requestPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                Intent intent = new Intent(ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + BuildConfig.APPLICATION_ID));
                startActivityForResult(intent, APP_STORAGE_ACCESS_REQUEST_CODE);
            }
        }
    }
    public float getDPIScale(){
        DisplayMetrics metrics = getResources().getDisplayMetrics();
        getWindowManager().getDefaultDisplay().getRealMetrics(metrics);
        return metrics.xdpi/120.0f;
    }
    public String getLanguage() {
        return Locale.getDefault().toString();
    }
    /*Handle permission request results*/
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == STORAGE_PERMISSION_CODE){
            if (grantResults.length > 0){
                //check each permission if granted or not
                boolean write = grantResults[0] == PackageManager.PERMISSION_GRANTED;
                boolean read = grantResults[1] == PackageManager.PERMISSION_GRANTED;

                if (write && read){
                    //External Storage permissions granted
                    Log.d(TAG, "onRequestPermissionsResult: External Storage permissions granted");
                }
                else{
                    //External Storage permission denied
                    Log.d(TAG, "onRequestPermissionsResult: External Storage permission denied");
                }
            }
        }
    }
    public float getVisibleBottom(){
        return visibleRect.bottom;
    }
    public float getVisibleTop(){
        return visibleRect.top;
    }
    public int getEvent(){
        if(keyboardEvents.isEmpty())return -1;
        int val = keyboardEvents.get(0);
        keyboardEvents.remove(0);
        return val;
    }
    public void showKeyboard(){
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                invisibleEditText.requestFocus();
                invisibleEditText.setFocusableInTouchMode(true);

                InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                imm.showSoftInput(invisibleEditText, InputMethodManager.SHOW_FORCED);
            }
        });
    }

    public void hideKeyboard()
    {
        Window win =this.getWindow();
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                InputMethodManager imm = ( InputMethodManager )getSystemService( Context.INPUT_METHOD_SERVICE );
                imm.hideSoftInputFromWindow( win.getDecorView().getWindowToken(), 0 );
            }
        });
    }
    public void pollKeyboard(){
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                keyboardEvents.add(-2);
                int pre = 0;
                boolean inserted = false;
                if(invisibleEditText.getSelectionEnd()!= invisibleEditText.getText().length()-8){
                    int distance =  invisibleEditText.getText().length()-invisibleEditText.getSelectionEnd()-8;
                    for(int c=0; c<distance;++c ){
                        //Left Arrow
                        keyboardEvents.add(1| 0x40000000);
                    }
                    distance =  invisibleEditText.getSelectionEnd()-(invisibleEditText.getText().length()-8);
                    for(int c=0; c<distance;++c ){
                        //Right Arrow
                        keyboardEvents.add(2| 0x40000000);
                    }
                }
                for (int c : invisibleEditText.getText().toString().chars().toArray()) {
                    if (pre < 8) {
                        if (c == '\1') {
                            pre++;
                            continue;
                        } else {
                            while (pre < 8) {
                                inserted=true;
                                // Backspace
                                keyboardEvents.add(11 | 0x40000000);
                                pre++;
                            }
                        }
                    }
                    if(pre>=invisibleEditText.getText().length()-8){
                        break;
                    }
                    pre++;
                    inserted=true;
                    //Enter
                    if(c=='\n'){keyboardEvents.add(13 |0x40000000);
                    }else keyboardEvents.add(c);
                }
                while (pre < 8) {
                    inserted=true;
                    keyboardEvents.add(11 | 0x40000000);
                    pre++;
                }
                if(inserted) {
                    invisibleEditText.setText("\1\1\1\1\1\1\1\1\2\2\2\2\2\2\2\2");
                    invisibleEditText.setSelection(invisibleEditText.getText().length()-8);
                }
                if(invisibleEditText.getSelectionEnd()!= invisibleEditText.getText().length()-8)
                    invisibleEditText.setSelection(invisibleEditText.getText().length()-8);
            }
        });
    }
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Window mRootWindow = getWindow();
        FrameLayout.LayoutParams mRparams = new FrameLayout.LayoutParams(FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT);
        invisibleEditText = new EditText(this);
        invisibleEditText.setLayoutParams(mRparams);
        invisibleEditText.setRawInputType(InputType.TYPE_CLASS_TEXT);
        invisibleEditText.setImeOptions(EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        keyboardEvents = new Vector<Integer>(5);
        View mRootView = mRootWindow.getDecorView().findViewById(android.R.id.content);
        ((FrameLayout)mRootView).addView(invisibleEditText);

        EnhancedNativeActivity activity = this;
        mRootView.getViewTreeObserver().addOnGlobalLayoutListener(
            new ViewTreeObserver.OnGlobalLayoutListener() {
                public void onGlobalLayout(){
                    Rect r = new Rect();
                    View view = mRootWindow.getDecorView();
                    view.getWindowVisibleDisplayFrame(r);
                    activity.visibleRect = r;
                }
            });

    }
    @Override
    public void onActivityResult(int requestCode, int resultCode,
                                 Intent returnIntent) {
        // If the selection didn't work
        if (resultCode != RESULT_OK) {
            // Exit without doing anything else
            return;
        } else {
            // Get the file's content URI from the incoming Intent
            Uri returnUri = returnIntent.getData();
            returnUri = Uri.parse(String.valueOf(returnUri));
            File file = new File(returnUri.getPath());//create path from uri
            final String[] split = file.getPath().split(":");//split the path.
            String filePath = split[1];//assign it to a string(your choice).

            /*
             * Try to open the file for "read" access using the
             * returned URI. If the file isn't found, write to the
             * error log and return.
             */
            Log.e("EnhancedNativeActivity", "Open File:"+file.getPath());

        }
    }
}
