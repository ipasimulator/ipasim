project (dyld)

add_library (dyld SHARED dyld.cpp)

# TODO: Add generated LLVM headers.
target_include_directories (dyld PUBLIC
    ${CMAKE_SOURCE_DIR}/deps/llvm/include)

target_compile_definitions (dyld PRIVATE BUILDING_DYLD)
