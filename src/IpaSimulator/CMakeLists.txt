set (SOURCE_FILES
    IpaSimulator.cpp)

add_library (IpaSimLibrary SHARED ${SOURCE_FILES})
add_prep_dep (IpaSimLibrary)

target_compile_options (IpaSimLibrary PRIVATE -std=c++17 -gcodeview)

target_include_directories (IpaSimLibrary PRIVATE
    C:/packages/cppwinrt.2017.4.6.1/build/native/include)

# Unicorn Engine
add_library (Unicorn SHARED IMPORTED)
set_target_properties (Unicorn PROPERTIES
    IMPORTED_LOCATION "${SOURCE_DIR}/lib/unicorn/unicorn.dll"
    IMPORTED_IMPLIB "${SOURCE_DIR}/lib/unicorn/unicorn.lib")
target_include_directories (Unicorn INTERFACE
    "${SOURCE_DIR}/lib/unicorn/include")

target_link_libraries (IpaSimLibrary PRIVATE WindowsApp.lib Unicorn)
