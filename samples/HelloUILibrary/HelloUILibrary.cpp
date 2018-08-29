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

#if 0
    // Manually call `UIApplicationInitialize`, which is an equivalent to `UIApplicationMain`
    // called by `main` in `HelloUI.exe`.
    if (HMODULE lib = win(LoadLibraryA("UIKit.dll"))) {
        if (FARPROC func = win(GetProcAddress(lib, "UIApplicationInitialize"))) {
            // void UIApplicationInitialize(const wchar_t* principalClassName, const wchar_t* delegateClassName)
            ((void(*)(const wchar_t *, const wchar_t *))func)(nullptr, L"HelloUIApp");
        }

        win(FreeLibrary(lib));
    }
#else
    // Let's try to load `HelloUI.exe`.
    // TODO: This doesn't work, why? Maybe try to load it as `.dll`...
    if (HMODULE lib = win(LoadLibraryA("HelloUI.dll"))) {

        // Find it's method `main`.
        if (FARPROC func = win(GetProcAddress(lib, "main"))) {

            // And call it.
            const char *name = "HelloUI.exe";
            ((int(*)(int, const char **))func)(1, &name);
        }

        win(FreeLibrary(lib));
    }
#endif
}
