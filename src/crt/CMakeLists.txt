add_library (crtstubs OBJECT stubs.cpp)

add_custom_command (OUTPUT "${SOURCE_DIR}/lib/crt/ucrtbased.dll.a"
    COMMAND "${SOURCE_DIR}/scripts/crt.cmd"
        "${SOURCE_DIR}/lib/crt/ucrtbased.dll"
        "${SOURCE_DIR}/lib/crt/ucrtbased.dll.a"
    COMMENT "Generate CRT import library"
    DEPENDS "${SOURCE_DIR}/scripts/crt.cmd"
        "${SOURCE_DIR}/lib/crt/ucrtbased.dll")
add_custom_target (crtlib DEPENDS "${SOURCE_DIR}/lib/crt/ucrtbased.dll.a")
