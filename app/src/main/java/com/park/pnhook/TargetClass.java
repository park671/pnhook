package com.park.pnhook;

import android.util.Log;

public class TargetClass {
    private static final String TAG = "TargetClass";

    public static void func0(int a, int b) {
        Log.d(TAG, "func0(): 1st print " + a + "," + b);
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        Log.d(TAG, "func0(): 2nd print " + a + "," + b);
    }

    public static int func1(int a, int b) {
        Log.d(TAG, "func1(): " + a + "," + b);
        return a + b;
    }

    public static int func2(int a, int b) {
        Log.d(TAG, "func2(): " + a + "," + b);
        return a - b;
    }

}
