#include <Windows.h> // for `GetCommandLineA`
#include <cstdlib>   // for `system`
#include <iostream>

using namespace std;

int main(int argc, char *argv[]) {
  // Make sure we are the only process executing in the current directory.
  HANDLE Lock =
      CreateFile(".ninja_wrapper_lock", GENERIC_READ, FILE_SHARE_READ, NULL,
                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (Lock == INVALID_HANDLE_VALUE) {
    cerr << "ninja-wrapper: couldn't open lock file" << endl;
    return 1;
  }
  OVERLAPPED SO;
  SO.Offset = 0;
  SO.OffsetHigh = 0;
  SO.hEvent = NULL;
  if (!LockFileEx(Lock, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &SO)) {
    cerr << "ninja-wrapper: couldn't acquire lock" << endl;
    return 1;
  }

  // Skip the executable name (source:
  // https://stackoverflow.com/a/36876057/9080566).
  char *s = GetCommandLineA();
  if (*s == '"') {
    ++s;
    while (*s)
      if (*s++ == '"')
        break;
  } else {
    while (*s && *s != ' ' && *s != '\t')
      ++s;
  }
  // Skip spaces preceding the first argument.
  while (*s == ' ' || *s == '\t')
    ++s;

  int RC = system(("ninja " + string(s)).c_str());

  // Unlock.
  UnlockFileEx(Lock, 0, 1, 0, &SO);

  return RC;
}
