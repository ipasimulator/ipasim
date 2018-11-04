list (APPEND CMAKE_MODULE_PATH "${SOURCE_DIR}/scripts")
include (CommonVariables)

file (MAKE_DIRECTORY "${CLANG_CMAKE_DIR}")
execute_process (
    COMMAND "${CMAKE_COMMAND}" -G Ninja
        -DLLVM_TARGETS_TO_BUILD=X86;ARM
        "-DLLVM_EXTERNAL_CLANG_SOURCE_DIR=${SOURCE_DIR}/deps/clang"
        "-DLLVM_EXTERNAL_LLD_SOURCE_DIR=${SOURCE_DIR}/deps/lld"
        "-DLLVM_EXTERNAL_LLDB_SOURCE_DIR=${SOURCE_DIR}/deps/lldb"
        -DCMAKE_BUILD_TYPE=Release
        "-DCMAKE_C_COMPILER=${LLVM_BIN_DIR}/clang-cl.exe"
        "-DCMAKE_CXX_COMPILER=${LLVM_BIN_DIR}/clang-cl.exe"
        "-DCMAKE_LINKER=${LLVM_BIN_DIR}/lld-link.exe"
        "${SOURCE_DIR}/deps/llvm"
    WORKING_DIRECTORY "${CLANG_CMAKE_DIR}")
