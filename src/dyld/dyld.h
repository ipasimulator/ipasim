#ifndef DYLD_H
#define DYLD_H

#include <llvm/BinaryFormat/MachO.h>

#define EXTERN extern "C"
#if defined(BUILDING_DYLD)
#define API EXTERN __declspec(dllexport)
#else
#define API EXTERN __declspec(dllimport)
#endif

typedef void(*_dyld_objc_notify_mapped)(unsigned count, const char* const paths[], const llvm::MachO::mach_header* const mh[]);
typedef void(*_dyld_objc_notify_init)(const char* path, const llvm::MachO::mach_header* mh);
typedef void(*_dyld_objc_notify_unmapped)(const char* path, const llvm::MachO::mach_header* mh);

API void _dyld_initialize(const llvm::MachO::mach_header* mh);
API void _dyld_objc_notify_register(_dyld_objc_notify_mapped mapped,
    _dyld_objc_notify_init init,
    _dyld_objc_notify_unmapped unmapped);

#endif // DYLD_H
