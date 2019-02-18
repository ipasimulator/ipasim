set (SOURCE_FILES
    dllmain.cpp
    InteropBase.mm
    ObjCHelpers.mm
    RTHelpers.mm
    RTObject.mm)

add_library (RTObjCInterop SHARED ${SOURCE_FILES})
add_prep_dep (RTObjCInterop)

target_include_directories (RTObjCInterop PRIVATE ${WOCFX_INCLUDE_DIRS})

target_compile_definitions (RTObjCInterop PRIVATE
    ${WINOBJC_DEFS}
    "OBJCWINRT_EXPORT=__declspec(dllexport)")

target_compile_options (RTObjCInterop PRIVATE ${WINOBJC_CLANG_OPTIONS})

target_link_libraries (RTObjCInterop PRIVATE
    ${WOCFX_LIBS}
    "-Wl,/def:${CMAKE_CURRENT_SOURCE_DIR}/export.def"
    # See #17.
    pthread)
