// dyld.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

using namespace llvm;
using namespace MachO;
using namespace std;

class library_guard {
public:
    library_guard(const char *name) : handle_(LoadLibraryA(name)) {}
    ~library_guard() {
        if (handle_) {
            FreeLibrary(handle_);
        }
    }
    operator bool() { return handle_; }
    FARPROC get_symbol(LPCSTR name) { return GetProcAddress(handle_, name); }
private:
    HMODULE handle_;
};

struct dylib_info {
    const char *path;
    const mach_header *header;
};

vector<dylib_info> dylibs;

void found_dylib(const char *path, const mach_header *mh) {
    // Check if we haven't already processed this one.
    for (auto &&dylib : dylibs) {
        if (dylib.header == mh) {
            return;
        }
    }

    // Save it.
    dylibs.push_back(dylib_info{ path, mh });

    // Find all `LC_LOAD_DYLIB` commands.
    auto cmd = reinterpret_cast<const load_command *>(mh + 1);
    for (size_t i = 0; i != mh->ncmds; ++i) {
        if (cmd->cmd == LC_LOAD_DYLIB) {
            auto dylib = reinterpret_cast<const dylib_command *>(cmd);

            // Get path.
            const char *name = reinterpret_cast<const char *>(dylib) + dylib->dylib.name;

            // Try to get its Mach-O header.
            if (auto lib = library_guard(name)) {
                if (auto sym = reinterpret_cast<const mach_header *>(lib.get_symbol("_mh_dylib_header"))) {

                    // If successfull, save it and find others recursively.
                    found_dylib(name, sym);
                }
            }
        }

        // Move to the next `load_command`.
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }
}
void _dyld_initialize(const mach_header* mh) {
    found_dylib(nullptr, mh);
}
void _dyld_objc_notify_register(_dyld_objc_notify_mapped mapped,
    _dyld_objc_notify_init init,
    _dyld_objc_notify_unmapped unmapped) {
    vector<const char *> paths;
    paths.reserve(dylibs.size());
    vector<const mach_header *> headers;
    headers.reserve(dylibs.size());
    for (auto &&dylib : dylibs) {
        paths.push_back(dylib.path);
        headers.push_back(dylib.header);
    }

    mapped(dylibs.size(), paths.data(), headers.data());

    for (auto &&dylib : dylibs) {
        init(dylib.path, dylib.header);
    }
}
