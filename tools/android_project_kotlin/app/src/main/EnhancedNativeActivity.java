package com.sky.SkyEmu;
import android.content.Context;
import android.view.inputmethod.InputMethodManager;
public class EnhancedNativeActivity extends android.app.NativeActivity {
    private static final String TAG = "EnhancedNativeActivity";
    public void print_hello(){
        android.util.Log.v(TAG, "Hello World\n");
    }
    public void showKeyboard() {
        InputMethodManager imm = ( InputMethodManager )getSystemService( Context.INPUT_METHOD_SERVICE );
        imm.showSoftInput( this.getWindow().getDecorView(), InputMethodManager.SHOW_FORCED );
    }
    public void hideKeyboard(){
        InputMethodManager imm = ( InputMethodManager )getSystemService( Context.INPUT_METHOD_SERVICE );
        imm.hideSoftInputFromWindow( this.getWindow().getDecorView().getWindowToken(), 0 );
    }
}
