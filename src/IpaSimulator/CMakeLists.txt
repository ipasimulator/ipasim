set (SOURCE_FILES
    DynamicLoader.cpp
    Emulator.cpp
    IpaSimulator.cpp
    LoadedLibrary.cpp
    MachO.cpp
    SysTranslator.cpp
    TextBlockStream.cpp)

add_library (IpaSimLibrary SHARED ${SOURCE_FILES})
add_prep_dep (IpaSimLibrary)

target_compile_options (IpaSimLibrary PRIVATE -std=c++17 -fcoroutines-ts)

set (LLVM_INCLUDE_DIRS
    "${CURRENT_CLANG_CMAKE_DIR}/include"
    "${SOURCE_DIR}/deps/llvm/include")
file (MAKE_DIRECTORY ${LLVM_INCLUDE_DIRS})

target_include_directories (IpaSimLibrary PRIVATE
    "${SOURCE_DIR}/include"
    ${LLVM_INCLUDE_DIRS})

target_compile_definitions (IpaSimLibrary PRIVATE
    # To enable coroutines support in C++/WinRT.
    _RESUMABLE_FUNCTIONS_SUPPORTED
    # Don't include `winsock.h`, it interferes with Unicorn's `winsock2.h`. See
    # <https://stackoverflow.com/a/1372836>.
    _WINSOCKAPI_
    $<$<CONFIG:Debug>:IPASIM_PRINT_EMU_INFO>)

# LIEF
add_custom_target (lief-x86
    COMMENT "LIEF"
    COMMAND ninja "lief-x86-${CMAKE_BUILD_TYPE}"
    BYPRODUCTS "${CURRENT_LIEF_CMAKE_DIR}/libLIEF.a"
    WORKING_DIRECTORY "${BINARY_DIR}"
    USES_TERMINAL)
add_library (LIEF STATIC IMPORTED)
set_target_properties (LIEF PROPERTIES
    IMPORTED_LOCATION "${CURRENT_LIEF_CMAKE_DIR}/libLIEF.a")
set (LIEF_INCLUDE_DIRS
    "${SOURCE_DIR}/deps/LIEF/include"
    "${SOURCE_DIR}/deps/LIEF/api/c/include"
    "${CURRENT_LIEF_CMAKE_DIR}/include")
# CMake would complain if some include dirs didn't exist.
file (MAKE_DIRECTORY ${LIEF_INCLUDE_DIRS})
target_include_directories (LIEF SYSTEM INTERFACE ${LIEF_INCLUDE_DIRS})
target_compile_options (LIEF INTERFACE
    "-include${CMAKE_CURRENT_SOURCE_DIR}/my_iso646.h")
target_compile_definitions (LIEF INTERFACE NOMINMAX)
target_link_libraries (LIEF INTERFACE $<IF:$<CONFIG:Debug>,msvcrtd,msvcrt>)
add_dependencies (LIEF lief-x86)

# Libffi
add_custom_target (Libffi-x86
    COMMENT "Libffi"
    COMMAND ninja "Libffi-x86-${CMAKE_BUILD_TYPE}"
    BYPRODUCTS "${CURRENT_LIBFFI_CMAKE_DIR}/lib/libffi.lib"
    WORKING_DIRECTORY "${BINARY_DIR}"
    USES_TERMINAL)
add_library (ffi STATIC IMPORTED)
set_target_properties (ffi PROPERTIES
    IMPORTED_LOCATION "${CURRENT_LIBFFI_CMAKE_DIR}/lib/libffi.lib")
add_dependencies (ffi Libffi-x86)
set (LIBFFI_INCLUDE_DIRS
    "${SOURCE_DIR}/deps/Libffi/build/include")
# CMake would complain if some include dirs didn't exist.
file (MAKE_DIRECTORY ${LIBFFI_INCLUDE_DIRS})
target_include_directories (ffi SYSTEM INTERFACE ${LIBFFI_INCLUDE_DIRS})
# From `/deps/Libffi/CMakeLists.txt`
target_compile_definitions (ffi INTERFACE FFI_BUILDING)

# Copy ANGLE binaries.
add_custom_command (
    OUTPUT "${CURRENT_IPASIM_CMAKE_DIR}/bin/libEGL.dll"
        "${CURRENT_IPASIM_CMAKE_DIR}/bin/libGLESv2.dll"
    COMMAND "${CMAKE_COMMAND}" "-DSOURCE_DIR=${SOURCE_DIR}"
        "-DBINARY_DIR=${BINARY_DIR}"
        "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
        -P "${SOURCE_DIR}/scripts/CopyANGLE.cmake"
    COMMENT "Copy ANGLE binaries"
    DEPENDS "${SOURCE_DIR}/scripts/CopyANGLE.cmake"
        "${SOURCE_DIR}/scripts/CommonVariables.cmake")
add_custom_target (AngleBinaries
    DEPENDS "${CURRENT_IPASIM_CMAKE_DIR}/bin/libEGL.dll"
        "${CURRENT_IPASIM_CMAKE_DIR}/bin/libGLESv2.dll")
add_dependencies (IpaSimLibrary AngleBinaries)

target_link_libraries (IpaSimLibrary PRIVATE WindowsApp.lib unicorn LIEF ffi)

# TODO: Actually build AppX with this target.
add_custom_target (IpaSimApp)
add_dependencies (IpaSimApp IpaSimLibrary CodeGen Frameworks)
