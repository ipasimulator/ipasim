list (APPEND CMAKE_MODULE_PATH "${SOURCE_DIR}/scripts")
include (CommonVariables)

file (MAKE_DIRECTORY "${LIEF_CMAKE_DIR}")
execute_process (
    COMMAND "${CMAKE_COMMAND}" -G Ninja
        -DLIEF_PYTHON_API=off
        -DLIEF_DOC=off
        "-DCMAKE_C_COMPILER=${CLANG_EXE}"
        -DCMAKE_C_COMPILER_ID=Clang
        "-DCMAKE_CXX_COMPILER=${CLANG_EXE}"
        -DCMAKE_CXX_COMPILER_ID=Clang
        "-DCMAKE_LINKER=${LLD_LINK_EXE}"
        "-DCMAKE_AR=${LLVM_BIN_DIR}/llvm-ar.exe"
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
        -DCMAKE_EXPORT_COMPILE_COMMANDS=On
        -DCMAKE_BUILD_TYPE=Debug
        "-DCMAKE_C_FLAGS=-DNOMINMAX -m32 -gcodeview"
        "-DCMAKE_CXX_FLAGS=-DNOMINMAX -m32 -gcodeview"
        "${SOURCE_DIR}/deps/LIEF"
    WORKING_DIRECTORY "${LIEF_CMAKE_DIR}")
