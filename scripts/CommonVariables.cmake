set (LLVM_BIN_DIR "C:/Program Files/LLVM/bin")

# See https://gitlab.kitware.com/cmake/cmake/issues/16259#note_158150.
# TODO: Don't set this when configuring WinObjC.
set (ENV{CFLAGS} -m32)
set (ENV{CXXFLAGS} -m32)

set (CLANG_CMAKE_DIR "${BINARY_DIR}/clang-x86-Release")
set (DEBUG_CLANG_CMAKE_DIR "${BINARY_DIR}/clang-x86-Debug")
set (IPASIM_CMAKE_DIR "${BINARY_DIR}/ipasim-x86-Debug")
set (WINOBJC_CMAKE_DIR "${BINARY_DIR}/winobjc-x86-Debug")

# First we set the compiler to the original Clang, because at least it exists.
# We will change this after the project is configured (and compiler is tested).
# See #2.
set (CLANG_EXE "${LLVM_BIN_DIR}/clang.exe")
set (LLD_LINK_EXE "${LLVM_BIN_DIR}/lld-link.exe")

set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
