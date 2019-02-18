set (LLVM_BIN_DIR "C:/Program Files/LLVM/bin")

set (CLANG_CMAKE_DIR "${BINARY_DIR}/clang-x86-Release")
set (DEBUG_CLANG_CMAKE_DIR "${BINARY_DIR}/clang-x86-Debug")
set (IPASIM_CMAKE_DIR "${BINARY_DIR}/ipasim-x86-Debug")
set (WINOBJC_CMAKE_DIR "${BINARY_DIR}/winobjc-x86-Debug")
set (LIEF_CMAKE_DIR "${BINARY_DIR}/lief-x86-Debug")

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

# See #13.
set (CF_PUBLIC_HEADERS
    # From `sdk-build.props`.
    Stream.subproj/CFStream.h
    String.subproj/CFStringEncodingExt.h
    Base.subproj/CoreFoundation.h
    Base.subproj/SwiftRuntime/TargetConditionals.h
    RunLoop.subproj/CFMessagePort.h
    Collections.subproj/CFBinaryHeap.h
    PlugIn.subproj/CFBundle.h
    Locale.subproj/CFCalendar.h
    Collections.subproj/CFBitVector.h
    Base.subproj/CFAvailability.h
    Collections.subproj/CFTree.h
    NumberDate.subproj/CFTimeZone.h
    Error.subproj/CFError.h
    Collections.subproj/CFBag.h
    PlugIn.subproj/CFPlugIn.h
    Parsing.subproj/CFXMLParser.h
    String.subproj/CFString.h
    Collections.subproj/CFSet.h
    Base.subproj/CFUUID.h
    NumberDate.subproj/CFDate.h
    Collections.subproj/CFDictionary.h
    Base.subproj/CFByteOrder.h
    AppServices.subproj/CFUserNotification.h
    Base.subproj/CFBase.h
    Preferences.subproj/CFPreferences.h
    Locale.subproj/CFLocale.h
    RunLoop.subproj/CFSocket.h
    Parsing.subproj/CFPropertyList.h
    Collections.subproj/CFArray.h
    RunLoop.subproj/CFRunLoop.h
    URL.subproj/CFURLAccess.h
    Locale.subproj/CFDateFormatter.h
    RunLoop.subproj/CFMachPort.h
    PlugIn.subproj/CFPlugInCOM.h
    Base.subproj/CFUtilities.h
    Parsing.subproj/CFXMLNode.h
    URL.subproj/CFURLComponents.h
    URL.subproj/CFURL.h
    Locale.subproj/CFNumberFormatter.h
    String.subproj/CFCharacterSet.h
    NumberDate.subproj/CFNumber.h
    Collections.subproj/CFData.h
    String.subproj/CFAttributedString.h
    Base.subproj/module.modulemap)
set (CF_PRIVATE_HEADERS
    # From `sdk-build.props`.
    Base.subproj/ForFoundationOnly.h
    Base.subproj/CFBridgeUtilities.h
    Base.subproj/CFPriv.h
    Base.subproj/CFRuntime.h
    PlugIn.subproj/CFBundlePriv.h
    Stream.subproj/CFStreamPriv.h
    String.subproj/CFRegularExpression.h)

function (add_prep_target cmd)
    add_custom_target (prep
        BYPRODUCTS "${BUILT_CLANG_EXE}" "${BUILT_LLD_LINK_EXE}"
        COMMENT "Superbuild"
        COMMAND ninja ${cmd}
        WORKING_DIRECTORY "${BINARY_DIR}"
        USES_TERMINAL)

    # Copy header files. See #13.
    list (TRANSFORM CF_PUBLIC_HEADERS PREPEND
        "${SOURCE_DIR}/deps/WinObjC/include/CoreFoundation/")
    list (TRANSFORM CF_PRIVATE_HEADERS PREPEND
        "${SOURCE_DIR}/deps/WinObjC/Frameworks/include/")
    add_custom_command (OUTPUT ${CF_PUBLIC_HEADERS} ${CF_PRIVATE_HEADERS}
        COMMAND "${CMAKE_COMMAND}" "-DSOURCE_DIR=${SOURCE_DIR}"
            "-DBINARY_DIR=${BINARY_DIR}"
            -P "${SOURCE_DIR}/scripts/CopyWocHeaders.cmake"
        COMMENT "Copy CoreFoundation headers"
        # TODO: Wrong usage of `DEPENDS`. And probably not just here!
        #DEPENDS "${CMAKE_SOURCE_DIR}/scripts/CopyWocHeaders.cmake"
        #    "${CMAKE_SOURCE_DIR}/scripts/CommonVariables.cmake"
    )
    add_custom_target (CoreFoundationHeaders
        DEPENDS ${CF_PUBLIC_HEADERS} ${CF_PRIVATE_HEADERS})
    add_dependencies (prep CoreFoundationHeaders)
endfunction (add_prep_target)

# HACK: Make `target` depend on clang.exe and lld-link.exe.
function (add_prep_dep target)
    # We don't need to build our Clang if we don't use it, though.
    # TODO: This is wrong. `prep` target does other things than just building
    # Clang.
    if (NOT USE_ORIG_CLANG)
        add_dependencies ("${target}" prep)
        get_target_property (srcs "${target}" SOURCES)
        set_source_files_properties (${srcs} PROPERTIES
            OBJECT_DEPENDS "${BUILT_CLANG_EXE};${BUILT_LLD_LINK_EXE}")
    endif (NOT USE_ORIG_CLANG)
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
    # (like NuGet package) and included from there. See also
    # `WinObjC.Language.Packaging.targets`, where it seems like all files from
    # `tools/include` and `tools/include_next` are copied somewhere (and
    # probably later included from there).
    "${SOURCE_DIR}/deps/WinObjC/tools/include"
    "${SOURCE_DIR}/deps/WinObjC/tools/include/xplat"
    "${SOURCE_DIR}/deps/WinObjC/tools/include/WOCStdLib")

set (WOCFX_INCLUDE_DIRS
    ${WINOBJC_INCLUDE_DIRS}
    # All frameworks have this one in their `*Lib.vcxproj`.
    "${SOURCE_DIR}/deps/WinObjC/Frameworks/include")
if (NOT CL_COMPILER)
    list (APPEND WOCFX_INCLUDE_DIRS
        # See comments at `WINOBJC_INCLUDE_DIRS`.
        "${SOURCE_DIR}/deps/WinObjC/tools/include_next/WOCStdLib"
        # From  NuGet package `cppwinrt`.
        C:/packages/cppwinrt.2017.4.6.1/build/native/include)
endif (NOT CL_COMPILER)

# Common Clang options for WinObjC projects.
set (WINOBJC_CLANG_OPTIONS
    # These come from `Islandwood.props`.
    -fblocks
    -fobjc-runtime=ios-11
    # Probably from `Islandwood.targets`.
    -includeWOCStdlib.h
    # From `sdk-build.props`.
    # TODO: Add `-Werror`?
    -Wno-c++17-extensions -Wno-nullability-completeness
    -Wno-c++17-compat-mangling -Wno-microsoft --system-header-prefix=winrt/)

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

# Shortcuts for compiler options (commented with their respective MSBuild
# equivalents).
set (COMPILE_AS_WINRT /ZW) # `<CompileAsWinRT>true</CompileAsWinRT>`
set (OBJC_ARC -fobjc-arc) # `<ObjectiveCARC>true</ObjectiveCARC>`

# Common linking options for WinObjC projects.
set (WINOBJC_LIBS
    # From `sdk-build.props`.
    -force:multiple)
if (NOT CL_COMPILER)
    list (TRANSFORM WINOBJC_LIBS PREPEND -Wl,)
endif (NOT CL_COMPILER)
list (APPEND WINOBJC_LIBS
    # From `Islandwood.props`
    WindowsApp.lib # Because it is specified as Windows Store app, probably.
    # From `ClangCompile.xml`.
    oldnames # For `--dependent-lib=oldnames`.
    # For `--dependent-lib=msvcrtd` + <https://docs.microsoft.com/en-us/cpp/
    # c-runtime-library/crt-library-features?view=vs-2017>.
    ucrtd vcruntimed msvcrtd msvcprtd)
set (WOCFX_LIBS
    ${WINOBJC_LIBS}
    woc-Logging
    objc
    dispatch
    # From `sdk-build.props`.
    Foundation
    Starboard
    CoreFoundation
    CFNetwork
    MobileCoreServices)

function (add_objcuwp_libs)
    # For `ObjCUWP*.lib`s specified in header files inside
    # `deps/WinObjC/include/Platform/Universal Windows/UWP`.
    link_directories ("../../deps/prebuilt/Universal Windows/x86")
endfunction (add_objcuwp_libs)

# This function is called by all WinObjC Frameworks (subdirectories in
# `/deps/WinObjC/Frameworks/`).
function (woc_framework name)
    add_prep_dep ("${name}")
    set_target_properties ("${name}" PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/Frameworks"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/Frameworks"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/Frameworks"
        PREFIX ""
        IMPORT_PREFIX "")
    add_dependencies (Frameworks "${name}")
endfunction (woc_framework)
