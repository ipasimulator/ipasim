extern "C" char _mh_dylib_header;
extern "C" void _dyld_initialize(void *);
extern "C" void _objc_init(void);

// This ensures that the initializer will run before others. We don't want that
// in `libobjc.dll` itself, though, because we actually want it's globals to be
// initialized before calling `_objc_init`.
#if !defined(BUILDING_OBJC)
#pragma init_seg(lib)
#endif

namespace {

struct DyldInitializer {
  DyldInitializer() {
    // Register itself within `dyld`.
    _dyld_initialize(&_mh_dylib_header);
    // Initialize the runtime if not already initialized.
    _objc_init();
  }
};

DyldInitializer DI;

} // namespace
