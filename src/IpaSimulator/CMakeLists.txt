set (SOURCE_FILES
    DynamicLoader.cpp
    IpaSimulator.cpp
    LoadedLibrary.cpp)

add_library (IpaSimLibrary SHARED ${SOURCE_FILES})
add_prep_dep (IpaSimLibrary)

target_compile_options (IpaSimLibrary PRIVATE -std=c++17 -fcoroutines-ts)

target_include_directories (IpaSimLibrary PRIVATE
    "${SOURCE_DIR}/include")

target_compile_definitions (IpaSimLibrary PRIVATE
    # To enable coroutines support in C++/WinRT.
    _RESUMABLE_FUNCTIONS_SUPPORTED
    # Don't include `winsock.h`, it interferes with Unicorn's `winsock2.h`. See
    # <https://stackoverflow.com/a/1372836>.
    _WINSOCKAPI_)

# LIEF
add_custom_target (lief-x86-Debug
    COMMENT "LIEF"
    COMMAND ninja lief-x86-Debug
    BYPRODUCTS "${LIEF_CMAKE_DIR}/libLIEF.a"
    WORKING_DIRECTORY "${BINARY_DIR}"
    USES_TERMINAL)
add_library (LIEF STATIC IMPORTED)
set_target_properties (LIEF PROPERTIES
    IMPORTED_LOCATION "${LIEF_CMAKE_DIR}/libLIEF.a")
set (LIEF_INCLUDE_DIRS
    "${SOURCE_DIR}/deps/LIEF/include"
    "${SOURCE_DIR}/deps/LIEF/api/c/include"
    "${LIEF_CMAKE_DIR}/include")
# CMake would complain if some include dirs didn't exist.
file (MAKE_DIRECTORY ${LIEF_INCLUDE_DIRS})
target_include_directories (LIEF INTERFACE ${LIEF_INCLUDE_DIRS})
target_compile_options (LIEF INTERFACE
    "-include${CMAKE_CURRENT_SOURCE_DIR}/my_iso646.h")
target_compile_definitions (LIEF INTERFACE NOMINMAX)
target_link_libraries (LIEF INTERFACE msvcrtd)
add_dependencies (LIEF lief-x86-Debug)

# Libffi
add_custom_target (Libffi-x86-Debug
    COMMENT "Libffi"
    COMMAND ninja Libffi-x86-Debug
    BYPRODUCTS "${LIBFFI_CMAKE_DIR}/lib/libffi.lib"
    WORKING_DIRECTORY "${BINARY_DIR}"
    USES_TERMINAL)
add_library (ffi STATIC IMPORTED)
set_target_properties (ffi PROPERTIES
    IMPORTED_LOCATION "${LIBFFI_CMAKE_DIR}/lib/libffi.lib")
add_dependencies (ffi Libffi-x86-Debug)
set (LIBFFI_INCLUDE_DIRS
    "${SOURCE_DIR}/deps/Libffi/build/include")
# CMake would complain if some include dirs didn't exist.
file (MAKE_DIRECTORY ${LIBFFI_INCLUDE_DIRS})
target_include_directories (ffi INTERFACE ${LIBFFI_INCLUDE_DIRS})
# From `/deps/Libffi/CMakeLists.txt`
target_compile_definitions (ffi INTERFACE FFI_BUILDING)

# Copy ANGLE binaries.
add_custom_command (
    OUTPUT "${IPASIM_CMAKE_DIR}/bin/libEGL.dll"
        "${IPASIM_CMAKE_DIR}/bin/libGLESv2.dll"
    COMMAND "${CMAKE_COMMAND}" "-DSOURCE_DIR=${SOURCE_DIR}"
        "-DBINARY_DIR=${BINARY_DIR}"
        -P "${SOURCE_DIR}/scripts/CopyANGLE.cmake"
    COMMENT "Copy ANGLE binaries"
    DEPENDS "${SOURCE_DIR}/scripts/CopyANGLE.cmake"
        "${SOURCE_DIR}/scripts/CommonVariables.cmake")
add_custom_target (AngleBinaries
    DEPENDS "${IPASIM_CMAKE_DIR}/bin/libEGL.dll"
        "${IPASIM_CMAKE_DIR}/bin/libGLESv2.dll")
add_dependencies (IpaSimLibrary AngleBinaries)

target_link_libraries (IpaSimLibrary PRIVATE WindowsApp.lib unicorn LIEF ffi)

# TODO: Actually build AppX with this target.
add_custom_target (IpaSimApp)
add_dependencies (IpaSimApp IpaSimLibrary CodeGen Frameworks)
