set (LLVM_BIN_DIR "C:/Program Files/LLVM/bin")

# See https://gitlab.kitware.com/cmake/cmake/issues/16259#note_158150.
# TODO: Don't set this when configuring WinObjC.
set (ENV{CFLAGS} -m32)
set (ENV{CXXFLAGS} -m32)

set (CLANG_CMAKE_DIR "${BINARY_DIR}/clang-x86-Release")
set (DEBUG_CLANG_CMAKE_DIR "${BINARY_DIR}/clang-x86-Debug")
set (IPASIM_CMAKE_DIR "${BINARY_DIR}/ipasim-x86-Debug")
set (WINOBJC_CMAKE_DIR "${BINARY_DIR}/winobjc-x86-Debug")

# First we set the compiler to the original Clang, because at least it exists.
# We will change this after the project is configured (and compiler is tested).
# See #2.
set (CLANG_EXE "${LLVM_BIN_DIR}/clang.exe")
set (LLD_LINK_EXE "${LLVM_BIN_DIR}/lld-link.exe")

# These are constants and shouldn't be changed (unlike the previous two).
set (ORIG_CLANG_EXE "${CLANG_EXE}")
set (ORIG_LLD_LINK_EXE "${LLD_LINK_EXE}")
set (BUILT_CLANG_EXE "${CLANG_CMAKE_DIR}/bin/clang.exe")
set (BUILT_LLD_LINK_EXE "${CLANG_CMAKE_DIR}/bin/lld-link.exe")

set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

function (add_prep_target cmd)
    add_custom_target (prep
        BYPRODUCTS "${BUILT_CLANG_EXE}" "${BUILT_LLD_LINK_EXE}"
        COMMENT "Superbuild"
        COMMAND ninja ${cmd}
        WORKING_DIRECTORY "${BINARY_DIR}"
        USES_TERMINAL)
endfunction (add_prep_target)

# HACK: Make `target` depend on clang.exe and lld-link.exe.
function (add_prep_dep target)
    add_dependencies ("${target}" prep)
    get_target_property (srcs "${target}" SOURCES)
    target_sources ("${target}" PUBLIC
        "${BUILT_CLANG_EXE}"
        "${BUILT_LLD_LINK_EXE}")
    set_source_files_properties ("${BUILT_CLANG_EXE}" "${BUILT_LLD_LINK_EXE}"
        PROPERTIES HEADER_FILE_ONLY ON GENERATED ON)
    set_source_files_properties (${srcs}
        PROPERTIES OBJECT_DEPENDS "${BUILT_CLANG_EXE};${BUILT_LLD_LINK_EXE}")
endfunction (add_prep_dep)

# Common include directories for WinObjC projects.
# TODO: Track them to source MSBuild files.
# TODO: Use them in every WinObjC project.
# TODO: Aren't some of those headers copied from somewhere else? (This should
# get revealed on a clean build, of course.)
set (WINOBJC_INCLUDE_DIRS
    # These come from `.tlog` files (MSBuild logs).
    "${SOURCE_DIR}/deps/WinObjC/include"
    "${SOURCE_DIR}/deps/WinObjC/include/xplat"
    "${SOURCE_DIR}/deps/WinObjC/deps/prebuilt/include"
    "${SOURCE_DIR}/deps/WinObjC/tools/deps/prebuilt/include"
    "${SOURCE_DIR}/deps/WinObjC/deps/prebuilt/include/icu"
    "${SOURCE_DIR}/deps/WinObjC/include/Platform/Universal Windows"
    # These just rose from the need, but weren't even in `.tlog` files like the
    # ones above. That's probably because they were copied to somewhere else
    # (like NuGet package) and included from there.
    "${SOURCE_DIR}/deps/WinObjC/tools/include"
    "${SOURCE_DIR}/deps/WinObjC/tools/include/xplat"
    "${SOURCE_DIR}/deps/WinObjC/tools/include/WOCStdLib")

# Common Clang options for WinObjC projects.
set (WINOBJC_CLANG_OPTIONS
    # These come from `Islandwood.props`.
    -fblocks
    -fobjc-runtime=ios-11
    # Probably from `Islandwood.targets`.
    -includeWOCStdlib.h
    # From `sdk-build.props`.
    -Wno-nullability-completeness)

# Common compiler definitions for WinObjC projects.
set (WINOBJC_DEFS
    OBJC_PORT
    # From `Islandwood.props`.
    WINAPI_FAMILY=WINAPI_FAMILY_APP
    _WINSOCK_DEPRECATED_NO_WARNINGS
    _HAS_EXCEPTIONS=0
    WINOBJC
    __WRL_NO_DEFAULT_LIB__
    # Without this, there is an error in header `Windows.UI.Notifications.h`
    # (and others) where macro `DEPRECATEDENUMERATOR` is used.
    # TODO: Don't define this, rather use older SDK (e.g., the one we used when
    # we successfully built WinObjC using MSBuild, i.e., 10.0.14393.0).
    DISABLE_WINRT_DEPRECATION
    # From `ClangCompile.xml`.
    # TODO: Change dynamically depending on `CMAKE_BUILD_TYPE`.
    _DEBUG _MT _DLL
    # Unicode
    UNICODE _UNICODE)

# Shortcuts for CL compiler options.
set (COMPILE_AS_WINRT /ZW) # MSBuild's `<CompileAsWinRT>true</CompileAsWinRT>`

# Common linking options for WinObjC projects.
set (WINOBJC_LIBS
    # From `sdk-build.props`.
    /force:multiple)
if (NOT CL_COMPILER)
    list (TRANSFORM WINOBJC_LIBS PREPEND -Wl,)
endif (NOT CL_COMPILER)
list (APPEND WINOBJC_LIBS
    # From `Islandwood.props`
    WindowsApp.lib) # Because it is specified as Windows Store app, probably.
