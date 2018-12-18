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
    OldClasses.subproj/List.m)
set (ORIG_ASM_FILES
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
list (TRANSFORM ORIG_ASM_FILES PREPEND "${SOURCE_DIR}/deps/objc4/runtime/")

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
    ${SOURCE_FILES}
    "${DYLD_INITIALIZER}")

# `runtime.c` needs to be compiled as C++ since there are errors otherwise.
# TODO: Why?
set_source_files_properties ("${SOURCE_DIR}/deps/libclosure/runtime.c"
    PROPERTIES COMPILE_OPTIONS -xc++)

# Build `.s` files specially. First compile them to Mach-O object files and then
# convert those to PE/COFF object files using utility `objconv.exe`.
add_library (objc-asm OBJECT ${ORIG_ASM_FILES})
set_target_properties (objc-asm PROPERTIES
    COMPILE_OPTIONS "-target;i386-apple-macosx10.13.0")
set (CONV_OBJS "")
list (LENGTH ORIG_ASM_FILES N_ASM)
foreach (I RANGE 1 "${N_ASM}")
    list (APPEND CONV_OBJS "${CMAKE_BINARY_DIR}/conv/${I}.obj")
endforeach (I)
add_custom_command (
    OUTPUT ${CONV_OBJS}
    COMMAND "${CMAKE_COMMAND}"
        "-DSOURCE_DIR=${SOURCE_DIR}"
        "-DTARGET_DIR=${CMAKE_BINARY_DIR}/conv"
        "-DASM_OBJECTS=$<TARGET_OBJECTS:objc-asm>"
        -P "${CMAKE_SOURCE_DIR}/src/objc/ConvAsmObj.cmake"
    USES_TERMINAL
    DEPENDS "${CMAKE_SOURCE_DIR}/src/objc/ConvAsmObj.cmake" objc-asm)
target_sources (objc PRIVATE ${CONV_OBJS})

# Common configuration for normal sources (target `objc`) and `.s` files (target
# `objc-asm`).
macro (config_target target)
    add_prep_dep ("${target}")

    target_compile_definitions ("${target}" PRIVATE
        BUILDING_OBJC=1
        NOMINMAX
        OBJC_PORT
        __OBJC2__=1)

    target_compile_options ("${target}" PRIVATE
        -fblocks
        -fobjc-runtime=macosx-10.13.0)

    target_include_directories ("${target}" PRIVATE
        "${SOURCE_DIR}/src/objc/include"
        "${SOURCE_DIR}/deps/apple-headers"
        "${SOURCE_DIR}/deps/libclosure")

    target_link_libraries ("${target}" PRIVATE pthread dyld)
endmacro (config_target)
config_target (objc)
config_target (objc-asm)

# Specify module definition file `libobjc.def`.
target_link_libraries (objc PRIVATE
    "-Wl,/def:${CMAKE_CURRENT_SOURCE_DIR}/libobjc.def")
