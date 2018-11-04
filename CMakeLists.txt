cmake_minimum_required (VERSION 3.11)

option (SUPERBUILD "Configure Clang and then the project itself." ON)

if (SUPERBUILD)

    # This branch is actually just something that could be written in Bash. But
    # this way it's at least more cross-platform.

    set (LLVM_BIN_DIR "C:/Program Files/LLVM/bin")

    # TODO: Maybe re-run nested CMakes every time (not only if the corresponding
    # folder doesn't exist).

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

    # Also configure Debug version of Clang.
    # TODO: Refactor this into a function.
    set (DEBUG_CLANG_CMAKE_DIR "${CMAKE_BINARY_DIR}/clang-x64-Debug")
    set (DEBUG_CLANG_INSTALL_DIR "${CMAKE_SOURCE_DIR}/build/clang-x64-Debug")
    if (NOT EXISTS "${DEBUG_CLANG_CMAKE_DIR}")
        file (MAKE_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}")
        execute_process (
            COMMAND ninja llvm-tblgen clang-tblgen
            WORKING_DIRECTORY "${CLANG_CMAKE_DIR}")
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
                "-DCMAKE_INSTALL_PREFIX=${DEBUG_CLANG_INSTALL_DIR}"
                -DCMAKE_INSTALL_MESSAGE=LAZY
                "${CMAKE_SOURCE_DIR}/deps/llvm"
                "-DLLVM_TABLEGEN=${CLANG_CMAKE_DIR}/bin/llvm-tblgen.exe"
                "-DCLANG_TABLEGEN=${CLANG_CMAKE_DIR}/bin/clang-tblgen.exe"
            WORKING_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}")
    endif (NOT EXISTS "${DEBUG_CLANG_CMAKE_DIR}")

    # First we set the compiler to the original Clang, because at least it
    # exists. We will change this after the project is configured (and
    # compiler is tested). See #2.
    set (CLANG_EXE "${LLVM_BIN_DIR}/clang.exe")
    set (LLD_LINK_EXE "${LLVM_BIN_DIR}/lld-link.exe")

    # Configure ipaSim project itself.
    set (IPASIM_CMAKE_DIR "${CMAKE_BINARY_DIR}/ipasim-x86-Debug")
    set (IPASIM_INSTALL_DIR "${CMAKE_SOURCE_DIR}/build/ipasim-x86-Debug")
    if (NOT EXISTS "${IPASIM_CMAKE_DIR}")
        file (MAKE_DIRECTORY "${IPASIM_CMAKE_DIR}")

        # See https://gitlab.kitware.com/cmake/cmake/issues/16259#note_158150.
        set (ENV{CFLAGS} -m32)
        set (ENV{CXXFLAGS} -m32)
        
        execute_process (
            COMMAND cmake -G Ninja
                -DSUPERBUILD=Off
                "-DCMAKE_C_COMPILER=${CLANG_EXE}"
                -DCMAKE_C_COMPILER_ID=Clang
                "-DCMAKE_CXX_COMPILER=${CLANG_EXE}"
                -DCMAKE_CXX_COMPILER_ID=Clang
                "-DCMAKE_LINKER=${LLD_LINK_EXE}"
                "-DCMAKE_AR=${LLVM_BIN_DIR}/llvm-ar.exe"
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
    
    # Now, the compiler was tested, so we can change it to our
    # possibly-not-yet-existing patched Clang. See #2.
    set (CLANG_EXE "${CLANG_CMAKE_DIR}/bin/clang.exe")
    set (LLD_LINK_EXE "${CLANG_CMAKE_DIR}/bin/lld-link.exe")
    # TODO: With the original Clang, it works, with ours, it doesn't. What do
    # we miss here?
    set (CMAKE_C_COMPILER "${CLANG_EXE}")
    set (CMAKE_CXX_COMPILER "${CLANG_EXE}")
    # Note that this is probably not actually used, but we keep it here for
    # consistency. Why is this not used? See below where we manually set
    # `-fuse-ld=lld-link`.
    set (CMAKE_LINKER "${LLD_LINK_EXE}")

    # Build `clang.exe`.
    add_custom_target (clang
        COMMENT "Clang"
        COMMAND ninja clang lld
        WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
        USES_TERMINAL)

    # This will generate `compile_commands.json`.
    set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

    # Simplify `CMAKE_CXX_LINK_EXECUTABLE` so that it actually works. (The
    # original also set some `-Wl` options which weren't compatible with MSVC
    # nor LLVM's MSVC-like linker.) The values were copied from
    # `C:\Program Files\CMake\share\cmake-3.11\Modules\CMakeCXXInformation.cmake`.
    # The original values were probably from
    # `Modules\Platform\Windows-GNU.cmake`. Also, we want to use `lld-link.exe`
    # instead of `CMAKE_CXX_COMPILER` for linking.
    set (CMAKE_CXX_LINK_EXECUTABLE
        "<CMAKE_CXX_COMPILER> -fuse-ld=lld-link <FLAGS> <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
    set (CMAKE_CXX_CREATE_SHARED_LIBRARY
        "<CMAKE_CXX_COMPILER> -fuse-ld=lld-link <CMAKE_SHARED_LIBRARY_CXX_FLAGS> <LANGUAGE_COMPILE_FLAGS> <LINK_FLAGS> <CMAKE_SHARED_LIBRARY_CREATE_CXX_FLAGS> <SONAME_FLAG><TARGET_SONAME> -o <TARGET> <OBJECTS> <LINK_LIBRARIES>")

    add_subdirectory (src)

endif (SUPERBUILD)
