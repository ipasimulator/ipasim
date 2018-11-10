# Patched sources from `/deps/objc4/runtime/`.
set (ORIG_SOURCE_FILES
    hashtable2.mm)
list (TRANSFORM ORIG_SOURCE_FILES PREPEND "${SOURCE_DIR}/deps/objc4/runtime/")

add_library (objc SHARED ${ORIG_SOURCE_FILES})

add_dependencies (objc prep)

target_compile_definitions (objc
    PRIVATE
        BUILDING_OBJC=1
    PUBLIC
        OBJC_PORT
        __OBJC2__=1)

target_include_directories (objc PUBLIC
    "${SOURCE_DIR}/src/objc/include/"
    "${SOURCE_DIR}/deps/apple-headers/")
