# Port of Apple's Objective-C runtime

## Preprocessor definitions

- `TARGET_OS_*` and `TARGET_CPU_*` - see `TargetConditionals.h` in MacOSX SDK
  for more information about these. The apps we are trying to emulate are iPhone
  apps, so we are defining `TARGET_OS_IOS` while building the `objc` runtime to
  simulate that environment.
- `__OBJC2__` - we are building the new runtime (which is the only one available
  on iPhones anyway).
- `HAVE_STRUCT_TIMESPEC` - needed for `<pthread.h>` from the pthreads-win32
  library.

## Proxy `#include`s

Because we definitely don't want to include the whole MacOSX SDK (for example,
`<stdio.h>` and similar should be included from MSVC instead) but some header
files are actually needed (they usually just contain macros, so it's safe to
include them), we added proxy `.h` files. These just `#include` the correct `.h`
from MacOSX SDK, or sometimes don't do anything, if we don't need the `.h`
actually (it was probably included through some other `.h` file). Also, only the
safe `.h` files are proxied this way, so it's ensured that nothing else is
included from the MacOSX SDK.

## Comment tags

- `[no-direct-keys]` - `pthread_key_t` (and it's equivalent `tls_key_t`) are
  integers on macOS, but not in pthreads-win32, so we cannot use integers for
  them as the original code does.
- `[format-error-pthread-self]` - There is a format error with `phtread_self()`.
  Original code supposed it returns a pointer, which it doesn't in
  pthreads-win32.
- `[use-unicorn-alloc]` - Maybe use unicorn's allocation engine instead.
- `[angle-brackets]` - We want to use `"..."` includes instead of `<objc/...>`
  ones.
- `[ptr-conversion]` - There is a conversion from `void *` to pointer of some
  specific type. Our compiler complains, so we add an explicit conversion.
- `[i386-asm]` - `objc-msg-i386.s` uses the old ABI (`!__OBJC2__`), so we use
  `objc-msg-simulator-i386.s` which uses the new ABI (`__OBJC2__`).
- `[unaligned]` - These instructions need aligned addresses to work, but we
  don't currently have them, so we use their unaligned variants.
  **TODO: It would be better to align the addresses instead. See e.g. Clang's
  `-falign-functions` (also do this in WinObjC `.dll`s).**
- `[classrefs]` - There is a bug which causes Objective-C classes imported
  across assembly boundaries to malfunction. It's because there's an added
  indirect reference which is not expected by the runtime. For example, in the
  `export-class` sample, the class is listed in `_objc_classrefs` section as
  `main.exe!__imp_OBJC_CLASS_$_TestClass`. That is a pointer to
  `testclass.dll!OBJC_CLASS_$_TestClass` containing the real class. It still
  doesn't crash immediately, because `Class` is expected to contain pointer to
  some class in its first field (the `isa` pointer). It just acts very
  strangely. This was fixed inside our patched Clang - see `[fixbind]`.
