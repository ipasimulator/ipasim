// compat.cpp: Contains some definitions of <Windows.h> functions not available in UWP.
// They are needed to make linker happy. They can have sample implementation for our
// purposes or be just stubs that should never be actually called.

#include "pch.h"
#include <Windows.h>

// Let's implement `IsWindowsVersionOrGreater` from <versionhelpers.h> used by `rang.hpp` from LIEF.
// It's defined in header file, so we implement the function it uses instead. We implement them so
// it behaves as if the Windows version is 10.0.0.

// Required by `IsWindowsVersionOrGreater`. Header copied from <winnt.h>.
extern "C" __declspec(dllexport) ULONGLONG NTAPI VerSetConditionMask(
    _In_ ULONGLONG ConditionMask,
    _In_ DWORD TypeMask,
    _In_ BYTE  Condition
) {
    // Do nothing.
    return ConditionMask;
}

// Required by `IsWindowsVersionOrGreater`. Header copied from <WinBase.h>.
extern "C" __declspec(dllexport) BOOL WINAPI VerifyVersionInfoW(
    _Inout_ LPOSVERSIONINFOEXW lpVersionInformation,
    _In_    DWORD dwTypeMask,
    _In_    DWORDLONG dwlConditionMask
) {
    // Return true if version required is <= 10.0.0.
    if (lpVersionInformation->dwMajorVersion < 10) { return true; }
    if (lpVersionInformation->dwMajorVersion == 10) {
        return lpVersionInformation->dwMinorVersion == 0 && lpVersionInformation->wServicePackMajor == 0;
    }
    return false;
}

// Required by `mbedtls_x509_crt_parse_path` from LIEF. Header copied from <WinBase.h>.
extern "C" __declspec(dllexport) int WINAPI lstrlenW(
    _In_ LPCWSTR lpString
) {
    return wcslen(lpString);
}
