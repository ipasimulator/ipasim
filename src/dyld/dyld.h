#ifndef DYLD_H
#define DYLD_H

#define EXTERN extern "C"
#if defined(BUILDING_DYLD)
#define API __declspec(dllexport) EXTERN
#else
#define API __declspec(dllimport) EXTERN
#endif

typedef void(*_dyld_objc_notify_mapped)(unsigned count, const char* const paths[], const struct mach_header* const mh[]);
typedef void(*_dyld_objc_notify_init)(const char* path, const struct mach_header* mh);
typedef void(*_dyld_objc_notify_unmapped)(const char* path, const struct mach_header* mh);

API void _dyld_initialize(const struct mach_header* mh);
API void _dyld_objc_notify_register(_dyld_objc_notify_mapped mapped,
    _dyld_objc_notify_init init,
    _dyld_objc_notify_unmapped unmapped);

#endif // DYLD_H
