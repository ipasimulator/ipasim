// compat.h: Contains some declarations of <Windows.h> functions not available in UWP.
// None of them is currently implemented, because they're not used, just declared in
// some header files we need to get compiled.

#include <Windows.h>

// Required by <LIEF/filesystem/path.h>.
extern "C" HANDLE WINAPI CreateFileW(
    __in      LPCTSTR lpFileName,
    __in      DWORD dwDesiredAccess,
    __in      DWORD dwShareMode,
    __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __in      DWORD dwCreationDisposition,
    __in      DWORD dwFlagsAndAttributes,
    __in_opt  HANDLE hTemplateFile
);
