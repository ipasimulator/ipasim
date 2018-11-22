cmake_minimum_required (VERSION 3.11)

# TODO: When calling ninja, hide message "no work to do".

option (SUPERBUILD "Configure Clang and then the project itself." ON)

if (SUPERBUILD)

    project (ipaSim-superbuild LANGUAGES NONE)

    set (SOURCE_DIR "${CMAKE_SOURCE_DIR}")
    set (BINARY_DIR "${CMAKE_BINARY_DIR}")

    list (APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/scripts")
    include (CommonVariables)

    function (add_superbuild_target name cmakeDir)
        add_custom_command (
            OUTPUT "${cmakeDir}/CMakeCache.txt"
            COMMAND "${CMAKE_COMMAND}"
                "-DSOURCE_DIR=${CMAKE_SOURCE_DIR}"
                "-DBINARY_DIR=${CMAKE_BINARY_DIR}"
                -P "${CMAKE_SOURCE_DIR}/scripts/${name}.cmake"
            USES_TERMINAL
            DEPENDS "${CMAKE_SOURCE_DIR}/scripts/${name}.cmake")
        add_custom_target ("config-${name}"
            DEPENDS "${cmakeDir}/CMakeCache.txt")
    endfunction (add_superbuild_target)

    add_superbuild_target (clang-x86-Release "${CLANG_CMAKE_DIR}")
    add_superbuild_target (clang-x86-Debug "${DEBUG_CLANG_CMAKE_DIR}")
    add_superbuild_target (ipaSim-x86-Debug "${IPASIM_CMAKE_DIR}")
    add_superbuild_target (winobjc-x86-Debug "${WINOBJC_CMAKE_DIR}")

    add_custom_target (tblgens-x86-Release
        COMMENT "Tablegens"
        COMMAND ninja llvm-tblgen clang-tblgen
        WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
        USES_TERMINAL
        DEPENDS config-clang-x86-Release)

    add_dependencies (config-clang-x86-Debug tblgens-x86-Release)

    add_custom_target (clang-x86-Release
        COMMENT "Clang"
        COMMAND ninja clang lld
        WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
        USES_TERMINAL
        DEPENDS config-clang-x86-Release)

    add_custom_target (clang-x86-Debug
        COMMENT "Clang"
        COMMAND ninja clang lld
        WORKING_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}"
        USES_TERMINAL
        DEPENDS config-clang-x86-Debug)

    add_custom_target (prep-ipaSim-x86-Debug
        COMMENT "Prepare ipaSim"
        DEPENDS config-ipaSim-x86-Debug config-winobjc-x86-Debug
            clang-x86-Release)

else (SUPERBUILD)

    option (USE_ORIG_CLANG "Use the original instead of our patched Clang. For \
testing purposes only." OFF)

    project (ipaSim LANGUAGES C CXX ASM)

    list (APPEND CMAKE_MODULE_PATH "${SOURCE_DIR}/scripts")
    include (CommonVariables)

    # Now, the compiler was tested, so we can change it to our
    # possibly-not-yet-existing patched Clang. See #2.
    set (ORIG_CLANG_EXE "${CLANG_EXE}")
    set (ORIG_LLD_LINK_EXE "${LLD_LINK_EXE}")
    if (USE_ORIG_CLANG)
        set (CLANG_EXE "${ORIG_CLANG_EXE}")
        set (LLD_LINK_EXE "${ORIG_LLD_LINK_EXE}")
    else (USE_ORIG_CLANG)
        set (CLANG_EXE "${CLANG_CMAKE_DIR}/bin/clang.exe")
        set (LLD_LINK_EXE "${CLANG_CMAKE_DIR}/bin/lld-link.exe")
    endif (USE_ORIG_CLANG)
    set (CMAKE_C_COMPILER "${CLANG_EXE}")
    set (CMAKE_CXX_COMPILER "${CLANG_EXE}")
    # Note that this is probably not actually used, but we keep it here for
    # consistency. Why is this not used? See below where we manually set
    # `-fuse-ld=lld-link`.
    set (CMAKE_LINKER "${LLD_LINK_EXE}")

    # Simplify `CMAKE_CXX_LINK_EXECUTABLE` so that it actually works. (The
    # original also set some `-Wl` options which weren't compatible with MSVC
    # nor LLVM's MSVC-like linker.) The values were copied from
    # `C:\Program Files\CMake\share\cmake-3.11\Modules\CMakeCXXInformation.cmake`.
    # The original values were probably from
    # `Modules\Platform\Windows-GNU.cmake`. Also, we want to use `lld-link.exe`
    # instead of `CMAKE_CXX_COMPILER` for linking.
    macro (update_commands lang)
        set ("CMAKE_${lang}_LINK_EXECUTABLE"
            "<CMAKE_CXX_COMPILER> -fuse-ld=lld-link <FLAGS> <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> -Wl,/implib:<TARGET_IMPLIB> <LINK_LIBRARIES>")
        set ("CMAKE_${lang}_CREATE_SHARED_LIBRARY"
            "<CMAKE_CXX_COMPILER> -fuse-ld=lld-link <CMAKE_SHARED_LIBRARY_CXX_FLAGS> <LANGUAGE_COMPILE_FLAGS> <LINK_FLAGS> <CMAKE_SHARED_LIBRARY_CREATE_CXX_FLAGS> <SONAME_FLAG><TARGET_SONAME> -o <TARGET> -Wl,/implib:<TARGET_IMPLIB> <OBJECTS> <LINK_LIBRARIES>")
    endmacro ()
    update_commands (C)
    update_commands (CXX)

    add_custom_target (prep
        COMMENT "Superbuild"
        COMMAND ninja prep-ipaSim-x86-Debug # TODO: Don't hardcode this.
        WORKING_DIRECTORY "${BINARY_DIR}"
        USES_TERMINAL)

    add_custom_target (config-winobjc-x86-Debug
        COMMENT "Configure WinObjC"
        COMMAND ninja config-winobjc-x86-Debug
        WORKING_DIRECTORY "${BINARY_DIR}"
        USES_TERMINAL)
    add_custom_target (winobjc-Logging
        COMMENT "WinObjC: Logging"
        COMMAND ninja Logging
        WORKING_DIRECTORY "${WINOBJC_CMAKE_DIR}"
        USES_TERMINAL
        DEPENDS config-winobjc-x86-Debug)

    # See https://medium.com/@alasher/colored-c-compiler-output-with-ninja-clang-gcc-10bfe7f2b949.
    option (FORCE_COLORED_OUTPUT "Always produce ANSI-colored output." ON)
    if (FORCE_COLORED_OUTPUT)
        add_compile_options (-fcolor-diagnostics -fansi-escape-codes)
    endif ()

    # Common file used by many libraries.
    set (DYLD_INITIALIZER "${SOURCE_DIR}/src/dyld/dyld_initializer.cpp")

    add_subdirectory (src)
    add_subdirectory (deps/WinObjC/Frameworks)

endif (SUPERBUILD)
