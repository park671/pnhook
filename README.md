# pnhook ![pnhook](https://github.com/user-attachments/assets/7b67af47-aaef-440b-856f-e5ea7b585450)
park's native hook library for android/linux

## Completed features:
1. fake dlopen() / dlsym(): bypass the Android native dlopen namespace restrictions, e.g. libart.so
2. inline hook by instruction address (method entry address)
3. inline hook by libName & methodName
4. other minor features

## Incomplete features:
1. hook ART virtual machine Java methods (partly work, but still many unresolved issues).

## Interface:
```C
struct PHookHandle {
    //this is the origin method that u hook.
    void *backup;
};

//get a method by name
void *methodForName(const char *libName, const char *methodName);

//hook a method by pointer
struct PHookHandle *hookMethodPtr(void *methodPtr, void *hookDelegate);

//hook a method by name
struct PHookHandle *hookMethod(const char *libName, const char *methodName, void *hookDelegate);

//unhook a method
bool unhookMethod(struct PHookHandle *);
```

## Demo:
```C
//hook a method named "StrictMath_cos()" in "libopenjdk.so"
//this method is the native impl of Java's "java.lang.StrictMath.cos()"

//hold the hook handle, will be used if u want to call the origin method
static struct PHookHandle *strictMathCosHookHandle = nullptr;

//this method is used for processing hook logic (delegate the origin method)
extern "C" jdouble StrictMathCosHookDelegate(jdouble d) {
    const char *TEST_TAG = "strict_math_hook";
    logd(TEST_TAG, "StrictMath_cos() hook delegate called!");
    logd(TEST_TAG, "native input: %0.2f", d);
    //invoke origin func
    jdouble result = ((jdouble (*)(jdouble d)) strictMathCosHookHandle->backup)(d);
    jdouble mock = 671.123;
    logd(TEST_TAG, "input: %0.2f, output:%0.2f, mock:%0.2f", d, result, mock);
    return mock;
}

//invoke this mehthod to apply the hook!
bool hookStrictMathCos() {
    logd(PNHOOK_BRIDGE_TAG, "inline hook start");
    const char *libName = "libopenjdk.so";
    const char *methodName = "StrictMath_cos";
    void *hookDelegatePtr = (void *) StrictMathCosHookDelegate;
    strictMathCosHookHandle = hookMethod(libName, methodName, hookDelegatePtr);
    if (strictMathCosHookHandle != nullptr) {
        return true;
    } else {
        return false;
    }
}
```
