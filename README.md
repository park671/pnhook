# pnhook ![pnhook](https://github.com/user-attachments/assets/7b67af47-aaef-440b-856f-e5ea7b585450)
park's native hook library for android/linux

Completed features:
1. fake dlopen() / dlsym(): bypass the Android native dlopen namespace restrictions, e.g. libart.so
2. inline hook by instruction address (method entry address)
3. inline hook by libName & methodName
4. other minor features

Incomplete features:
1. hook ART virtual machine Java methods (partly work, but still many unresolved issues).
