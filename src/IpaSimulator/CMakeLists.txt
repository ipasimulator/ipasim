set (SOURCE_FILES
    IpaSimulator.cpp)

add_executable (IpaSimulator ${SOURCE_FILES})
add_prep_dep (IpaSimulator)

target_compile_options (IpaSimulator PRIVATE -std=c++17 -gcodeview)

target_include_directories (IpaSimulator PRIVATE
    C:/packages/cppwinrt.2017.4.6.1/build/native/include)

target_link_libraries (IpaSimulator PRIVATE WindowsApp.lib)
