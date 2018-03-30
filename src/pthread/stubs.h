// stubs.h : Contains WinAPI's functions used by pthreads-win32 library which are not available for UWP apps.
// Their bodies just contain some default behavior - e.g. they return a state that indicates failure.
//

#ifndef PTW32_STUBS_H
#define PTW32_STUBS_H

#include <Windows.h>

BOOL SetThreadContext(HANDLE hThread, const CONTEXT *lpContext);
UINT GetSystemDirectory(LPTSTR lpBuffer, UINT uSize);
HMODULE LoadLibrary(LPCTSTR lpFileName);

#endif
