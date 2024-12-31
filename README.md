# pnhook
![pnhook512_linear](https://github.com/user-attachments/assets/63aa5a7a-cef2-4a8e-9c27-f78fc28137e0)
park's native hook library for android/linux

Completed features:
1. fake dlopen() / dlsym(): bypass the Android native dlopen namespace restrictions, e.g. libart.so
2. inline hook by instruction address (method entry address)
3. inline hook by libName & methodName
4. other minor features

Incomplete features:
1. hook ART virtual machine Java methods (partly work, but still many unresolved issues).
