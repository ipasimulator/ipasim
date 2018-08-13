# `dyld`

`dyld` is a standalone `.dll` library that can initialize Objective-C libraries and executables.
The main Objective-C library or executable simply calls function `_dyld_initialize`.
That function in turn reads the image's Mach-O header (injected by our patched `lld-link` directly into the image) to determine dependant libraries (and their dependant libraries, recursively).
It also implements function `_dyld_objc_notify_register` which is used by `libobjc` to initialize Objective-C runtime.
