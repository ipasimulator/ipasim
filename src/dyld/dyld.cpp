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

struct dylib_handlers {
    _dyld_objc_notify_mapped mapped;
    _dyld_objc_notify_init init;
    _dyld_objc_notify_unmapped unmapped;
};

vector<dylib_info> dylibs;
vector<dylib_handlers> handlers;

static const uint8_t *bytes(const void *ptr) { return reinterpret_cast<const uint8_t *>(ptr); }
void found_dylib(const char *path, const mach_header *mh) {
    // Check if we haven't already processed this one.
    for (auto &&dylib : dylibs) {
        if (dylib.header == mh) {
            return;
        }
    }

    // Save it.
    dylibs.push_back(dylib_info{ path, mh });

    // Parse load commands.
    intptr_t slide = 0;
    auto cmd = reinterpret_cast<const load_command *>(mh + 1);
    for (size_t i = 0; i != mh->ncmds; ++i) {

        // Find all `LC_LOAD_DYLIB` commands.
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

        // Find segment `__DATA`.
        else if (cmd->cmd == LC_SEGMENT) {
            auto seg = reinterpret_cast<const segment_command *>(cmd);
            if (seg->segname == string("__DATA")) {

                // And inside this segment, find section `__fixbind`.
                auto sect = reinterpret_cast<const section *>(bytes(cmd) + sizeof(segment_command));
                for (size_t j = 0; j != seg->nsects; ++j) {
                    if (sect->sectname == string("__fixbind")) {

                        // In this section, iterate through all the addresses and fix them up.
                        uint32_t count = sect->size >> 2;
                        uintptr_t ***data = (decltype(data))((uint8_t *)(sect->addr) + slide);
                        for (size_t k = 0; k != count; ++k, ++data) {
                            if (*data) {
                                **data = (uintptr_t *)***data;
                            }
                        }
                    }

                    // Move to the next `section`.
                    sect = reinterpret_cast<const section *>(bytes(sect) + sizeof(section));
                }
            }
            // Also look for segment `__TEXT` to compute `slide`.
            else if (seg->segname == string("__TEXT")) {
                slide = (uintptr_t)mh - seg->vmaddr;
            }
        }

        // Move to the next `load_command`.
        cmd = reinterpret_cast<const load_command *>(bytes(cmd) + cmd->cmdsize);
    }
}
void handle_dylibs(size_t startIndex) {

    vector<const char *> paths;
    paths.reserve(dylibs.size() - startIndex);
    vector<const mach_header *> headers;
    headers.reserve(dylibs.size() - startIndex);
    for (size_t i = startIndex; i != dylibs.size(); ++i) {
        paths.push_back(dylibs[i].path);
        headers.push_back(dylibs[i].header);
    }

    for (auto &&handler : handlers) {
        handler.mapped(headers.size(), paths.data(), headers.data());

        for (size_t i = startIndex; i != dylibs.size(); ++i) {
            handler.init(dylibs[i].path, dylibs[i].header);
        }
    }
}
void _dyld_initialize(const mach_header* mh) {

    size_t handled = dylibs.size();

    // TODO: Find out the path.
    found_dylib(nullptr, mh);

    // Handle new dylibs.
    handle_dylibs(handled);
}
void _dyld_objc_notify_register(_dyld_objc_notify_mapped mapped,
    _dyld_objc_notify_init init,
    _dyld_objc_notify_unmapped unmapped) {

    handlers.push_back(dylib_handlers{ mapped, init, unmapped });
    handle_dylibs(0);
}
