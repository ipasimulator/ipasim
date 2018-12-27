set (CLANG_OPTIONS -fobjc-runtime=ios-11)

add_library (testclass SHARED testclass.mm)
target_compile_options (testclass PRIVATE ${CLANG_OPTIONS})
target_link_libraries (testclass PRIVATE objc)

add_executable (export-class main.mm)
target_compile_options (export-class PRIVATE ${CLANG_OPTIONS})
target_link_libraries (export-class PRIVATE dyld objc testclass)
