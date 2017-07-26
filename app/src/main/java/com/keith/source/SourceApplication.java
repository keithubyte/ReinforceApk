package com.keith.source;

import android.app.Application;
import android.util.Log;

/**
 * Author: Keith
 * Date: 2017/7/26
 */

public class SourceApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        Log.e(Tag.LOG_TAG, "This is source apk.");
    }

}
