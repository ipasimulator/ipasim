# Patched sources from `/deps/objc4/runtime/`.
set (ORIG_SOURCE_FILES
    hashtable2.mm
    maptable.mm
    NSObject.mm
    objc-accessors.mm
    objc-auto.mm
    objc-block-trampolines.mm
    objc-cache-old.mm
    objc-cache.mm
    objc-class-old.mm
    objc-class.mm
    objc-errors.mm
    objc-exception.mm
    objc-file-old.mm
    objc-file.mm
    objc-initialize.mm
    objc-layout.mm
    objc-load.mm
    objc-loadmethod.mm
    objc-lockdebug.mm
    objc-opt.mm
    objc-os.mm
    objc-references.mm
    objc-runtime-new.mm
    objc-runtime-old.mm
    objc-runtime.mm
    objc-sel-old.mm
    objc-sel-set.mm
    objc-sel.mm
    objc-sync.mm
    objc-typeencoding.mm
    objc-weak.mm
    Object.mm
    Protocol.mm
    OldClasses.subproj/List.m
    Messengers.subproj/objc-msg-arm.s
    Messengers.subproj/objc-msg-arm64.s
    Messengers.subproj/objc-msg-i386.s
    Messengers.subproj/objc-msg-simulator-i386.s
    Messengers.subproj/objc-msg-simulator-x86_64.s
    Messengers.subproj/objc-msg-x86_64.s
    a1a2-blocktramps-arm.s
    a1a2-blocktramps-arm64.s
    a1a2-blocktramps-i386.s
    a1a2-blocktramps-x86_64.s
    a2a3-blocktramps-arm.s
    a2a3-blocktramps-i386.s
    a2a3-blocktramps-x86_64.s
    objc-sel-table.s)
list (TRANSFORM ORIG_SOURCE_FILES PREPEND "${SOURCE_DIR}/deps/objc4/runtime/")

# Sources from `/deps/libclosure/`.
set (LIBCLOSURE_SOURCE_FILES
    data.c
    runtime.c)
list (TRANSFORM LIBCLOSURE_SOURCE_FILES PREPEND
    "${SOURCE_DIR}/deps/libclosure/")

set (SOURCE_FILES
    dladdr.mm
    getsecbyname.mm
    cxxabi.mm
    stubs.mm)

add_library (objc SHARED
    ${ORIG_SOURCE_FILES}
    ${LIBCLOSURE_SOURCE_FILES}
    ${SOURCE_FILES})

# `runtime.c` needs to be compiled as C++ since there are errors otherwise.
# TODO: Why?
set_source_files_properties ("${SOURCE_DIR}/deps/libclosure/runtime.c"
    PROPERTIES COMPILE_OPTIONS -xc++)

add_dependencies (objc prep)

target_compile_definitions (objc
    PRIVATE
        BUILDING_OBJC=1
        NOMINMAX
    PUBLIC
        OBJC_PORT
        __OBJC2__=1)

target_compile_options (objc PRIVATE
    -fblocks
    -fobjc-runtime=macosx-10.13.0)

target_include_directories (objc PUBLIC
    "${SOURCE_DIR}/src/objc/include"
    "${SOURCE_DIR}/deps/apple-headers"
    "${SOURCE_DIR}/deps/libclosure")

target_link_libraries (objc pthread dyld)
