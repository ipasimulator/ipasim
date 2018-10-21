# TODO: Make the super build run only once as discussed here:
# https://stackoverflow.com/q/48339178.

cmake_minimum_required (VERSION 3.11)
project (ipaSim LANGUAGES NONE)

# Configure Clang if it hasn't been configured yet.
set (CLANG_CMAKE_DIR "${CMAKE_BINARY_DIR}/clang-x64-Release")
set (CLANG_INSTALL_DIR "${CMAKE_SOURCE_DIR}/build/clang-x64-Release")
if (NOT EXISTS "${CLANG_CMAKE_DIR}")
    file (MAKE_DIRECTORY "${CLANG_CMAKE_DIR}")
    execute_process (
        COMMAND cmake -G Ninja
            -DLLVM_TARGETS_TO_BUILD=X86;ARM
            "-DLLVM_EXTERNAL_CLANG_SOURCE_DIR=${CMAKE_SOURCE_DIR}/deps/clang"
            "-DLLVM_EXTERNAL_LLD_SOURCE_DIR=${CMAKE_SOURCE_DIR}/deps/lld"
            "-DLLVM_EXTERNAL_LLDB_SOURCE_DIR=${CMAKE_SOURCE_DIR}/deps/lldb"
            -DCMAKE_BUILD_TYPE=Release
            "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
            "-DCMAKE_LINKER=${CMAKE_LINKER}"
            "-DCMAKE_INSTALL_PREFIX=${CLANG_INSTALL_DIR}"
            -DCMAKE_INSTALL_MESSAGE=LAZY
            "${CMAKE_SOURCE_DIR}/deps/llvm"
        WORKING_DIRECTORY "${CLANG_CMAKE_DIR}")
endif (NOT EXISTS "${CLANG_CMAKE_DIR}")

# Build `clang.exe`.
add_custom_target (clang
    COMMENT "Clang"
    # TODO: Change this to `install-clang` when we are ready.
    COMMAND ninja install-llvm-headers
    WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
    USES_TERMINAL)

# This will generate `compile_commands.json`.
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory (src)
