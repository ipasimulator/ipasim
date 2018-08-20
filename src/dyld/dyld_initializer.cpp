// Compiled with:
// ..\..\build\bin\clang -target i386-pc-windows-msvc -c dyld_initializer.cpp -o ..\..\Debug\dyld_initializer.obj -g -gcodeview

extern "C" char _mh_dylib_header;
extern "C" void _dyld_initialize(void*);
extern "C" void _objc_init(void);

__attribute__((constructor(1)))
static void initializer() {
    // Register itself within `dyld`.
    _dyld_initialize(&_mh_dylib_header);
    // Initialize the runtime if not already initialized.
    _objc_init();
}
