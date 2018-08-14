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

void _dyld_initialize(const mach_header* mh) {
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

                    // If successfull, save it.
                    dylibs.push_back(dylib_info{ name, sym });
                }
            }
        }

        // Move to the next `load_command`.
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }
}
