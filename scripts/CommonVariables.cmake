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

# These are constants and shouldn't be changed (unlike the previous two).
set (ORIG_CLANG_EXE "${CLANG_EXE}")
set (ORIG_LLD_LINK_EXE "${LLD_LINK_EXE}")
set (BUILT_CLANG_EXE "${CLANG_CMAKE_DIR}/bin/clang.exe")
set (BUILT_LLD_LINK_EXE "${CLANG_CMAKE_DIR}/bin/lld-link.exe")

set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

function (add_prep_target cmd)
    add_custom_target (prep
        BYPRODUCTS "${BUILT_CLANG_EXE}" "${BUILT_LLD_LINK_EXE}"
        COMMENT "Superbuild"
        COMMAND ninja ${cmd}
        WORKING_DIRECTORY "${BINARY_DIR}"
        USES_TERMINAL)
endfunction (add_prep_target)

# HACK: Make `target` depend on clang.exe and lld-link.exe.
function (add_prep_dep target)
    add_dependencies ("${target}" prep)
    get_target_property (srcs "${target}" SOURCES)
    target_sources ("${target}" PUBLIC
        "${BUILT_CLANG_EXE}"
        "${BUILT_LLD_LINK_EXE}")
    set_source_files_properties ("${BUILT_CLANG_EXE}" "${BUILT_LLD_LINK_EXE}"
        PROPERTIES HEADER_FILE_ONLY ON GENERATED ON)
    set_source_files_properties (${srcs}
        PROPERTIES OBJECT_DEPENDS "${BUILT_CLANG_EXE};${BUILT_LLD_LINK_EXE}")
endfunction (add_prep_dep)
