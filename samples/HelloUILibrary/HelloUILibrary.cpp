// HelloUILibrary.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

template<typename T>
static T win(T result) {
    if (!result) {
        // Retrieve the system error message for the last-error code.
        LPVOID lpMsgBuf;
        DWORD dw = GetLastError();
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            dw,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMsgBuf,
            0, NULL);

        // Display the error message.
        OutputDebugStringW((LPCTSTR)lpMsgBuf);

        LocalFree(lpMsgBuf);
    }
    return result;
}

extern "C" __declspec(dllexport) void start() {
    win(LoadLibraryA("CoreFoundation.dll"));

    if (HMODULE lib = win(LoadLibraryA("UIKit.dll"))) {
        if (FARPROC func = win(GetProcAddress(lib, "UIApplicationMain"))) {
            // int UIApplicationMain(int argc, char* argv[], void* principalClassName, void* delegateClassName)
            ((int(*)(int, char *, void *, void *))func)(0, nullptr, nullptr, nullptr);
        }

        win(FreeLibrary(lib));
    }

    // Let's try to load `HelloUI.exe`.
    if (HMODULE lib = win(LoadLibraryA("HelloUI.exe"))) {

        // Find it's method `main`.
        if (FARPROC func = win(GetProcAddress(lib, "main"))) {

            // And call it.
            const char *name = "HelloUI.exe";
            ((int(*)(int, const char **))func)(1, &name);
        }

        win(FreeLibrary(lib));
    }
}
