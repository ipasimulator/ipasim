set (SOURCE_FILES
    IpaSimulator.cpp)

add_library (IpaSimLibrary SHARED ${SOURCE_FILES})
add_prep_dep (IpaSimLibrary)

target_compile_options (IpaSimLibrary PRIVATE -std=c++17)

target_include_directories (IpaSimLibrary PRIVATE
    # For `WrapperIndex.hpp`
    "${SOURCE_DIR}/src/HeadersAnalyzer/include")

# Unicorn Engine
add_library (Unicorn SHARED IMPORTED)
set_target_properties (Unicorn PROPERTIES
    IMPORTED_LOCATION "${SOURCE_DIR}/lib/unicorn/unicorn.dll"
    IMPORTED_IMPLIB "${SOURCE_DIR}/lib/unicorn/unicorn.lib")
target_include_directories (Unicorn INTERFACE
    "${SOURCE_DIR}/lib/unicorn/include")

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

target_link_libraries (IpaSimLibrary PRIVATE WindowsApp.lib Unicorn LIEF)

# TODO: Actually build AppX with this target.
add_custom_target (IpaSimApp)
add_dependencies (IpaSimApp IpaSimLibrary CodeGen Frameworks)
