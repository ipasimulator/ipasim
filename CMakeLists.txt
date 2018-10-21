# TODO: Make the super build run only once as discussed here:
# https://stackoverflow.com/q/48339178.

cmake_minimum_required (VERSION 3.11)
project (ipaSim LANGUAGES NONE)

# This will generate `compile_commands.json`.
# TODO: Probably not needed in this super-build file.
#set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

#add_subdirectory (deps)
#add_subdirectory (src)

include (ExternalProject)

# TODO: This doesn't support multi-config generators right now. See also
# https://stackoverflow.com/a/30011890.
# TODO: Also, this has Release configuration hard-coded. But sometimes we want
# to debug Clang.
ExternalProject_Add (clang
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/deps/llvm"
    CMAKE_ARGS -DLLVM_TARGETS_TO_BUILD=X86;ARM
        "-DLLVM_EXTERNAL_CLANG_SOURCE_DIR=${CMAKE_SOURCE_DIR}/deps/clang"
        "-DLLVM_EXTERNAL_LLD_SOURCE_DIR=${CMAKE_SOURCE_DIR}/deps/lld"
        "-DLLVM_EXTERNAL_LLDB_SOURCE_DIR=${CMAKE_SOURCE_DIR}/deps/lldb"
        -DCMAKE_BUILD_TYPE=Release
        "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
        "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        "-DCMAKE_LINKER=${CMAKE_LINKER}"
    BUILD_COMMAND ""
    INSTALL_COMMAND "${CMAKE_COMMAND}" --build . --target install-clang)

ExternalProject_Add (ipasim-src
    SOURCE_DIR "${CMAKE_SOURCE_DIR}"
    DEPENDS clang)

add_custom_target (ipasim
    DEPENDS ipasim-src)
