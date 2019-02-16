cmake_minimum_required (VERSION 3.12.2)

# TODO: When calling ninja, hide message "no work to do".

option (SUPERBUILD "Configure Clang and then the project itself." ON)

set (CL_COMPILER OFF)

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
            # TODO: This should also depend on CommonVariables.cmake, right?
            # TODO: Wrong usage of `DEPENDS`.
            DEPENDS "${CMAKE_SOURCE_DIR}/scripts/${name}.cmake")
        add_custom_target ("config-${name}"
            DEPENDS "${cmakeDir}/CMakeCache.txt")
    endfunction (add_superbuild_target)

    add_superbuild_target (clang-x86-Release "${CLANG_CMAKE_DIR}")
    add_superbuild_target (clang-x86-Debug "${DEBUG_CLANG_CMAKE_DIR}")
    add_superbuild_target (ipaSim-x86-Debug "${IPASIM_CMAKE_DIR}")
    add_superbuild_target (winobjc-x86-Debug "${WINOBJC_CMAKE_DIR}")
    add_superbuild_target (lief-x86-Debug "${LIEF_CMAKE_DIR}")

    add_custom_target (tblgens-x86-Release
        COMMENT "Tablegens"
        COMMAND ninja llvm-tblgen clang-tblgen
        WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
        DEPENDS config-clang-x86-Release)

    add_dependencies (config-clang-x86-Debug tblgens-x86-Release)

    add_custom_target (clang-x86-Release
        COMMENT "Clang"
        COMMAND ninja clang lld
        WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
        DEPENDS config-clang-x86-Release)

    add_custom_target (clang-x86-Debug
        COMMENT "Clang"
        COMMAND ninja clang lld
        WORKING_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}"
        DEPENDS config-clang-x86-Debug)

    add_custom_target (prep-ipaSim-x86-Debug
        COMMENT "Prepare ipaSim"
        DEPENDS config-ipaSim-x86-Debug config-winobjc-x86-Debug
            clang-x86-Release)

    add_custom_target (ipaSim-x86-Debug
        COMMENT "ipaSim"
        # TODO: Change to `IpaSimApp` when it's ready.
        COMMAND ninja IpaSimLibrary
        WORKING_DIRECTORY "${IPASIM_CMAKE_DIR}"
        DEPENDS config-ipaSim-x86-Debug)

    add_custom_target (lief-x86-Debug
        COMMENT "LIEF"
        COMMAND ninja LIB_LIEF_STATIC
        WORKING_DIRECTORY "${LIEF_CMAKE_DIR}"
        DEPENDS config-lief-x86-Debug)

else (SUPERBUILD)

    option (USE_ORIG_CLANG "Use the original instead of our patched Clang. For \
testing purposes only." OFF)

    project (ipaSim LANGUAGES C CXX ASM)

    list (APPEND CMAKE_MODULE_PATH "${SOURCE_DIR}/scripts")
    include (CommonVariables)

    # Now, the compiler was tested, so we can change it to our
    # possibly-not-yet-existing patched Clang. See #2.
    if (NOT USE_ORIG_CLANG)
        set (CLANG_EXE "${BUILT_CLANG_EXE}")
        set (LLD_LINK_EXE "${BUILT_LLD_LINK_EXE}")
    endif (NOT USE_ORIG_CLANG)
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
            "<CMAKE_CXX_COMPILER> -fuse-ld=lld-link <FLAGS> \
<CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> \
-Wl,/implib:<TARGET_IMPLIB> <LINK_LIBRARIES>")
        set ("CMAKE_${lang}_CREATE_SHARED_LIBRARY"
            "<CMAKE_CXX_COMPILER> -fuse-ld=lld-link \
<CMAKE_SHARED_LIBRARY_CXX_FLAGS> <LANGUAGE_COMPILE_FLAGS> <LINK_FLAGS> \
<CMAKE_SHARED_LIBRARY_CREATE_CXX_FLAGS> <SONAME_FLAG><TARGET_SONAME> \
-o <TARGET> -Wl,/implib:<TARGET_IMPLIB> <OBJECTS> <LINK_LIBRARIES>")
    endmacro ()
    update_commands (C)
    update_commands (CXX)

    add_prep_target (prep-ipaSim-x86-Debug) # TODO: Don't hardcode this.

    add_custom_target (config-winobjc-x86-Debug
        COMMENT "Configure WinObjC"
        COMMAND ninja config-winobjc-x86-Debug
        WORKING_DIRECTORY "${BINARY_DIR}")
    function (add_woc_lib name)
        add_custom_target ("woc-${name}-build"
            BYPRODUCTS "${WINOBJC_CMAKE_DIR}/bin/${name}.dll"
                "${WINOBJC_CMAKE_DIR}/bin/${name}.lib"
            COMMENT "WinObjC: ${name}"
            COMMAND ninja ${name}
            WORKING_DIRECTORY "${WINOBJC_CMAKE_DIR}"
            DEPENDS config-winobjc-x86-Debug)
        add_library ("woc-${name}" SHARED IMPORTED)
        set_target_properties ("woc-${name}" PROPERTIES
            IMPORTED_LOCATION "${WINOBJC_CMAKE_DIR}/bin/${name}.dll"
            IMPORTED_IMPLIB "${WINOBJC_CMAKE_DIR}/bin/${name}.lib")
    endfunction (add_woc_lib)
    # TODO: Create these somehow automatically. See
    # https://cmake.org/pipermail/cmake/2010-September/039388.html
    add_woc_lib (WOCStdLib)
    add_woc_lib (Logging)
    add_woc_lib (Starboard)
    add_woc_lib (WinObjCRT)
    add_woc_lib (Foundation)
    add_woc_lib (Accelerate)
    # See `tools/Logging/CMakeLists.txt`.
    target_include_directories (woc-Logging INTERFACE
        "${SOURCE_DIR}/deps/WinObjC/tools/Logging/include")

    # Library `libdispatch.dll`.
    # TODO: Don't hardcode the architecture, maybe even build it from sources
    # (they are in `deps/WinObjC/deps/3rdparty/libdispatch`).
    add_library (dispatch SHARED IMPORTED)
    set_target_properties (dispatch PROPERTIES
        IMPORTED_LOCATION "${SOURCE_DIR}/deps/WinObjC/tools/deps/prebuilt/\
Universal Windows/x86/libdispatch.dll"
        IMPORTED_IMPLIB "${SOURCE_DIR}/deps/WinObjC/tools/deps/prebuilt/\
Universal Windows/x86/libdispatch.lib")

    function (add_prebuilt_lib_core name dllname)
        add_library ("${name}" SHARED IMPORTED)
        set_target_properties ("${name}" PROPERTIES
            IMPORTED_LOCATION "${SOURCE_DIR}/deps/WinObjC/deps/prebuilt/\
Universal Windows/x86/${dllname}.dll"
            IMPORTED_IMPLIB "${SOURCE_DIR}/deps/WinObjC/deps/prebuilt/\
Universal Windows/x86/${name}.lib")
    endfunction (add_prebuilt_lib_core)
    function (add_prebuilt_lib name)
        add_prebuilt_lib_core ("${name}" "${name}")
    endfunction (add_prebuilt_lib)

    # Library ICU. See <http://site.icu-project.org/>.
    # TODO: Use CMake function `FindICU` or something like that instead.
    function (add_icu_lib name)
        add_prebuilt_lib_core ("icu${name}" "icu${name}57")
    endfunction (add_icu_lib)
    add_icu_lib (dt)
    add_icu_lib (in)
    add_icu_lib (uc)

    add_prebuilt_lib (libxml2)

    add_library (cassowary STATIC IMPORTED)
    set_target_properties (cassowary PROPERTIES
        IMPORTED_LOCATION "${SOURCE_DIR}/deps/WinObjC/deps/prebuilt/\
Universal Windows/x86/cassowary-0.60-Debug.lib")

    # NuGet package ANGLE.WindowsStore.
    set (ANGLE_DIR "C:/packages/ANGLE.WindowsStore.2.1.13")
    add_library (EGL SHARED IMPORTED)
    set_target_properties (EGL PROPERTIES
        IMPORTED_LOCATION "${ANGLE_DIR}/bin/UAP/Win32/libEGL.dll"
        IMPORTED_IMPLIB "${ANGLE_DIR}/bin/UAP/Win32/libEGL.lib")
    target_include_directories (EGL INTERFACE "${ANGLE_DIR}/Include")
    add_library (GLESv2 SHARED IMPORTED)
    set_target_properties (GLESv2 PROPERTIES
        IMPORTED_LOCATION "${ANGLE_DIR}/bin/UAP/Win32/libGLESv2.dll"
        IMPORTED_IMPLIB "${ANGLE_DIR}/bin/UAP/Win32/libGLESv2.lib")
    target_include_directories (GLESv2 INTERFACE "${ANGLE_DIR}/Include")

    # See
    # https://medium.com/@alasher/colored-c-compiler-output-with-ninja-clang-gcc-10bfe7f2b949.
    # TODO: Do this for CL.exe, too.
    option (FORCE_COLORED_OUTPUT "Always produce ANSI-colored output." ON)
    if (FORCE_COLORED_OUTPUT)
        add_compile_options (-fcolor-diagnostics -fansi-escape-codes)
    endif ()

    # Common file used by many libraries.
    set (DYLD_INITIALIZER "${SOURCE_DIR}/src/dyld/dyld_initializer.cpp")

    # Target grouping all WinObjC Frameworks. See function `woc_framework`.
    add_custom_target (Frameworks)

    add_subdirectory (src)
    add_subdirectory (deps/WinObjC/Frameworks)
    add_subdirectory (samples)

endif (SUPERBUILD)
