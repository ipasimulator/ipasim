add_library (crtstubs OBJECT stubs.cpp)
add_prep_dep (crtstubs)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set (D_POSTFIX "d")
else ()
    set (D_POSTFIX "")
endif ()

add_custom_command (OUTPUT "${SOURCE_DIR}/deps/crt/ucrtbase${D_POSTFIX}.dll.a"
    COMMAND "${SOURCE_DIR}/scripts/crt.cmd"
        "${SOURCE_DIR}/deps/crt/ucrtbase${D_POSTFIX}.dll"
        "${SOURCE_DIR}/deps/crt/ucrtbase${D_POSTFIX}.dll.a"
        "ucrtbase${D_POSTFIX}"
        "UCRTBASE$<UPPER_CASE:${D_POSTFIX}>"
    COMMENT "Generate CRT import library"
    DEPENDS "${SOURCE_DIR}/scripts/crt.cmd"
        "${SOURCE_DIR}/deps/crt/ucrtbase${D_POSTFIX}.dll")
add_custom_target (crtlib DEPENDS
    "${SOURCE_DIR}/deps/crt/ucrtbase${D_POSTFIX}.dll.a")
