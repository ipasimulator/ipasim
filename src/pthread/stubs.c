#include "stubs.h"

BOOL SetThreadContext(HANDLE hThread, const CONTEXT *lpContext) {
	return FALSE;
}
UINT GetSystemDirectory(LPTSTR lpBuffer, UINT uSize) {
	return 0;
}
HMODULE LoadLibrary(LPCTSTR lpFileName) {
	return NULL;
}
