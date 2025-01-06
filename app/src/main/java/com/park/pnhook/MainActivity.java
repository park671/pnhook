package com.park.pnhook;

import android.app.Activity;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;

import androidx.annotation.Nullable;

import com.park.pnhook.databinding.ActivityMainBinding;

import java.lang.reflect.Method;

public class MainActivity extends Activity {

    private static final String TAG = "MainActivity";

    private ActivityMainBinding binding;

    @Override
    protected void attachBaseContext(Context newBase) {
        super.attachBaseContext(newBase);
        try {
            Method method1 = StubArtMethodClass.class.getMethod("func1");
            Method method2 = StubArtMethodClass.class.getMethod("func2");
            if (NativeBridge.initEnv(method1, method2)) {
                Log.d(TAG, "native env init success");
            } else {
                Log.e(TAG, "native env init fail");
            }
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(LayoutInflater.from(this));
        binding.inlineHookButton.setOnClickListener(v -> {
            if (NativeBridge.inlineHook()) {
                Log.d(TAG, "inline hook success");
                binding.inlineHookButton.setTextColor(Color.GREEN);
            } else {
                Log.d(TAG, "inline hook fail");
                binding.inlineHookButton.setTextColor(Color.RED);
            }
        });
        binding.triggerButton.setOnClickListener(v -> {
            Log.d(TAG, "invoke native target start");
            double angleInDegrees = 60;
            double angleInRadians = StrictMath.toRadians(angleInDegrees);
            Log.d(TAG, "java input=" + angleInRadians);
            double result = StrictMath.cos(angleInRadians);
            Log.d(TAG, "cos(60 degrees) = " + result);
            binding.inlineHookTextView.setText("cos(60 degrees) = " + result);
        });

        binding.invokeTargetButton.setOnClickListener(v -> {
            new Thread(() -> {
                Log.d(TAG, "thread start");
                TargetClass.func0(1, 7);
                Log.d(TAG, "thread finish");
            }).start();
        });
        binding.trampolineButton.setOnClickListener(v -> {
            try {
                Method func0 = TargetClass.class.getMethod("func0", int.class, int.class);
                NativeBridge.injectTrampoline(func0);
            } catch (NoSuchMethodException e) {
                throw new RuntimeException(e);
            }
        });
        setContentView(binding.getRoot());
    }
}
