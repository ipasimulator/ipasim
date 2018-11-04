list (APPEND CMAKE_MODULE_PATH "${SOURCE_DIR}/scripts")
include (CommonVariables)

file (MAKE_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}")
execute_process (
    COMMAND cmake -G Ninja
        -DLLVM_TARGETS_TO_BUILD=X86;ARM
        "-DLLVM_EXTERNAL_CLANG_SOURCE_DIR=${SOURCE_DIR}/deps/clang"
        "-DLLVM_EXTERNAL_LLD_SOURCE_DIR=${SOURCE_DIR}/deps/lld"
        "-DLLVM_EXTERNAL_LLDB_SOURCE_DIR=${SOURCE_DIR}/deps/lldb"
        -DCMAKE_BUILD_TYPE=Release
        "-DCMAKE_C_COMPILER=${LLVM_BIN_DIR}/clang-cl.exe"
        "-DCMAKE_CXX_COMPILER=${LLVM_BIN_DIR}/clang-cl.exe"
        "-DCMAKE_LINKER=${LLVM_BIN_DIR}/lld-link.exe"
        "-DLLVM_TABLEGEN=${CLANG_CMAKE_DIR}/bin/llvm-tblgen.exe"
        "-DCLANG_TABLEGEN=${CLANG_CMAKE_DIR}/bin/clang-tblgen.exe"
        -DCMAKE_EXPORT_COMPILE_COMMANDS=On
        "${SOURCE_DIR}/deps/llvm"
    WORKING_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}")
