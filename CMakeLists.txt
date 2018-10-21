# TODO: Make the super build run only once as discussed here:
# https://stackoverflow.com/q/48339178.

cmake_minimum_required (VERSION 3.11)
project (ipaSim LANGUAGES NONE)

# This will generate `compile_commands.json`.
# TODO: Probably not needed in this super-build file.
#set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

#add_subdirectory (deps)
#add_subdirectory (src)

# TODO: Use `add_custom_command` whose output is `clang.exe`.
add_custom_target (clang-mkdir
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/clang-x64-Release")
add_custom_target (clang
    DEPENDS clang-mkdir
    COMMAND cmake -G Ninja
        -DLLVM_TARGETS_TO_BUILD=X86;ARM
        "-DLLVM_EXTERNAL_CLANG_SOURCE_DIR=${CMAKE_SOURCE_DIR}/deps/clang"
        "-DLLVM_EXTERNAL_LLD_SOURCE_DIR=${CMAKE_SOURCE_DIR}/deps/lld"
        "-DLLVM_EXTERNAL_LLDB_SOURCE_DIR=${CMAKE_SOURCE_DIR}/deps/lldb"
        -DCMAKE_BUILD_TYPE=Release
        "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
        "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        "-DCMAKE_LINKER=${CMAKE_LINKER}"
        "-DCMAKE_INSTALL_PREFIX=${CMAKE_SOURCE_DIR}/build/clang-x64-Release"
        -DCMAKE_INSTALL_MESSAGE=LAZY
        "${CMAKE_SOURCE_DIR}/deps/llvm"
    # TODO: Change this to `install-clang` when we are ready.
    COMMAND ninja install-llvm-headers
    COMMENT "Clang"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/clang-x64-Release"
    USES_TERMINAL)

add_custom_target (ipasim
    DEPENDS clang)
