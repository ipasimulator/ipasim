set (SOURCE_FILES
    IpaSimulator.cpp)

add_library (IpaSimLibrary SHARED ${SOURCE_FILES})
add_prep_dep (IpaSimLibrary)

target_compile_options (IpaSimLibrary PRIVATE -std=c++17 -gcodeview)

target_include_directories (IpaSimLibrary PRIVATE
    C:/packages/cppwinrt.2017.4.6.1/build/native/include)

target_link_libraries (IpaSimLibrary PRIVATE WindowsApp.lib)
