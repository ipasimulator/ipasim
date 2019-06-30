// MachOInitializer.cpp: Contains class `MachOInitializer`.

#define IPASIM_IMPORT extern "C" __declspec(dllimport)

extern "C" char _mh_dylib_header;
IPASIM_IMPORT void ipaSim_register(void *); // From `IpaSimLibrary`
IPASIM_IMPORT void _objc_init(void);        // From `objc`

// This ensures that the initializer will run before others. We don't want that
// in `libobjc.dll` itself, though, because we actually want it's globals to be
// initialized before calling `_objc_init`.
#if !defined(BUILDING_OBJC)
#pragma init_seg(lib)
#endif

namespace {

// Ensures the current library is initialized via RAII.
struct MachOInitializer {
  MachOInitializer() {
    // Register itself within `IpaSimLibrary`.
    ipaSim_register(&_mh_dylib_header);
    // Initialize the Objective-C runtime.
    _objc_init();
  }
};

MachOInitializer MI;

} // namespace
