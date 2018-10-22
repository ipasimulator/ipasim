cmake_minimum_required (VERSION 3.11)

option (SUPERBUILD "Configure Clang and then the project itself." ON)

if (SUPERBUILD)

    # This branch is actually just something that could be written in Bash. But
    # this way it's at least more cross-platform.

    set (LLVM_BIN_DIR "C:/Program Files/LLVM/bin")

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
                "-DCMAKE_C_COMPILER=${LLVM_BIN_DIR}/clang-cl.exe"
                "-DCMAKE_CXX_COMPILER=${LLVM_BIN_DIR}/clang-cl.exe"
                "-DCMAKE_LINKER=${LLVM_BIN_DIR}/lld-link.exe"
                "-DCMAKE_INSTALL_PREFIX=${CLANG_INSTALL_DIR}"
                -DCMAKE_INSTALL_MESSAGE=LAZY
                "${CMAKE_SOURCE_DIR}/deps/llvm"
            WORKING_DIRECTORY "${CLANG_CMAKE_DIR}")
    endif (NOT EXISTS "${CLANG_CMAKE_DIR}")

    # TODO: Use this when we're ready.
    #set (CLANG_EXE "${CLANG_INSTALL_DIR}/bin/clang.exe")
    set (CLANG_EXE "${LLVM_BIN_DIR}/clang.exe")
    # TODO: Also build and set linker.
    set (LLD_LINK_EXE "${LLVM_BIN_DIR}/lld-link.exe")

    # Configure ipaSim project itself.
    set (IPASIM_CMAKE_DIR "${CMAKE_BINARY_DIR}/ipasim-x86-Debug")
    set (IPASIM_INSTALL_DIR "${CMAKE_SOURCE_DIR}/build/ipasim-x86-Debug")
    if (NOT EXISTS "${IPASIM_CMAKE_DIR}")
        file (MAKE_DIRECTORY "${IPASIM_CMAKE_DIR}")
        execute_process (
            COMMAND cmake -G Ninja
                -DSUPERBUILD=Off
                "-DCMAKE_C_COMPILER=${CLANG_EXE}"
                -DCMAKE_C_COMPILER_ID=Clang
                "-DCMAKE_CXX_COMPILER=${CLANG_EXE}"
                -DCMAKE_CXX_COMPILER_ID=Clang
                "-DCMAKE_LINKER=${LLD_LINK_EXE}"
                "-DCMAKE_AR=C:/Program Files/LLVM/bin/llvm-ar.exe"
                -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
                "-DCMAKE_INSTALL_PREFIX=${IPASIM_INSTALL_DIR}"
                -DCMAKE_INSTALL_MESSAGE=LAZY
                "-DCLANG_CMAKE_DIR=${CLANG_CMAKE_DIR}"
                "${CMAKE_SOURCE_DIR}"
            WORKING_DIRECTORY "${IPASIM_CMAKE_DIR}")
    endif (NOT EXISTS "${IPASIM_CMAKE_DIR}")

    # TODO: Maybe add custom targets as shortcuts to targets inside folder
    # `ipasim-x86-Debug` and others.

else (SUPERBUILD)

    project (ipaSim)

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

endif (SUPERBUILD)
