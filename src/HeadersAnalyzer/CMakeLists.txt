# LLVM libraries.
add_custom_target (config-clang-x86-Debug
    COMMAND ninja config-clang-x86-Debug
    WORKING_DIRECTORY "${BINARY_DIR}"
    USES_TERMINAL)
function (add_clang_lib name)
    # Add imported library `${name}.lib`.
    add_library ("${name}" STATIC IMPORTED)
    set_target_properties ("${name}" PROPERTIES
        IMPORTED_LOCATION "${DEBUG_CLANG_CMAKE_DIR}/lib/${name}.lib")
    add_dependencies ("${name}" "gen-${name}")
    target_compile_definitions ("${name}" INTERFACE _DEBUG _MT _DLL)
    target_include_directories ("${name}" INTERFACE
        ../../deps/llvm/include
        "${DEBUG_CLANG_CMAKE_DIR}/include"
        ../../deps/clang/include
        "${DEBUG_CLANG_CMAKE_DIR}/tools/clang/include")
    target_link_libraries ("${name}" INTERFACE
        ucrtd vcruntimed msvcrtd msvcprtd)

    # Let CMake know how to generate `${name}.lib`.
    add_custom_command (
        OUTPUT "${DEBUG_CLANG_CMAKE_DIR}/lib/${name}.lib"
        COMMAND ninja "${name}"
        WORKING_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}"
        DEPENDS config-clang-x86-Debug
        USES_TERMINAL)
    add_custom_target ("gen-${name}"
        DEPENDS "${DEBUG_CLANG_CMAKE_DIR}/lib/${name}.lib")
endfunction (add_clang_lib)

set (CLANG_LIBS
    clangAnalysis
    clangARCMigrate
    clangAST
    clangASTMatchers
    clangBasic
    clangCodeGen
    clangCrossTU
    clangDriver
    clangDynamicASTMatchers
    clangEdit
    clangFormat
    clangFrontend
    clangFrontendTool
    clangIndex
    clangLex
    clangParse
    clangRewrite
    clangRewriteFrontend
    clangSema
    clangSerialization
    clangStaticAnalyzerCheckers
    clangStaticAnalyzerCore
    clangStaticAnalyzerFrontend
    clangTooling
    clangToolingASTDiff
    clangToolingCore
    clangToolingRefactor)

set (LLVM_LIBS
    LLVMAggressiveInstCombine
    LLVMAnalysis
    LLVMAsmParser
    LLVMAsmPrinter
    LLVMBinaryFormat
    LLVMBitReader
    LLVMBitWriter
    LLVMCodeGen
    LLVMCore
    LLVMCoroutines
    LLVMCoverage
    LLVMDebugInfoCodeView
    LLVMDebugInfoDWARF
    LLVMDebugInfoMSF
    LLVMDebugInfoPDB
    LLVMDemangle
    LLVMDlltoolDriver
    LLVMExecutionEngine
    LLVMFuzzMutate
    LLVMGlobalISel
    LLVMInstCombine
    LLVMInstrumentation
    LLVMInterpreter
    LLVMipo
    LLVMIRReader
    LLVMLibDriver
    LLVMLineEditor
    LLVMLinker
    LLVMLTO
    LLVMMC
    LLVMMCDisassembler
    LLVMMCJIT
    LLVMMCParser
    LLVMMIRParser
    LLVMObjCARCOpts
    LLVMObjCMetadata
    LLVMObject
    LLVMObjectYAML
    LLVMOption
    LLVMOrcJIT
    LLVMPasses
    LLVMProfileData
    LLVMRuntimeDyld
    LLVMScalarOpts
    LLVMSelectionDAG
    LLVMSupport
    LLVMSymbolize
    LLVMTarget
    LLVMTransformUtils
    LLVMVectorize
    LLVMWindowsManifest
    LLVMX86AsmParser
    LLVMX86AsmPrinter
    LLVMX86CodeGen
    LLVMX86Desc
    LLVMX86Disassembler
    LLVMX86Info
    LLVMX86Utils
    LLVMXRay)

foreach (lib ${CLANG_LIBS} ${LLVM_LIBS})
    add_clang_lib ("${lib}")
endforeach (lib)

# Library TAPI. See `docs/tapi.md`.
set (TAPI_SOURCES
    ../../deps/tapi/lib/Config/Version.cpp
    ../../deps/tapi/lib/Core/Architecture.cpp
    ../../deps/tapi/lib/Core/ArchitectureSet.cpp
    ../../deps/tapi/lib/Core/ArchitectureSupport.cpp
    ../../deps/tapi/lib/Core/AvailabilityInfo.cpp
    ../../deps/tapi/lib/Core/ConfigurationFile.cpp
    ../../deps/tapi/lib/Core/ExtendedInterfaceFile.cpp
    ../../deps/tapi/lib/Core/FileManager.cpp
    ../../deps/tapi/lib/Core/InterfaceFile.cpp
    ../../deps/tapi/lib/Core/InterfaceFileBase.cpp
    ../../deps/tapi/lib/Core/InterfaceFileManager.cpp
    ../../deps/tapi/lib/Core/MachODylibReader.cpp
    ../../deps/tapi/lib/Core/Path.cpp
    ../../deps/tapi/lib/Core/ReexportFileWriter.cpp
    ../../deps/tapi/lib/Core/Registry.cpp
    ../../deps/tapi/lib/Core/Symbol.cpp
    ../../deps/tapi/lib/Core/TextAPI_v1.cpp
    ../../deps/tapi/lib/Core/TextStub_v1.cpp
    ../../deps/tapi/lib/Core/TextStub_v2.cpp
    ../../deps/tapi/lib/Core/Utils.cpp
    ../../deps/tapi/lib/Core/XPI.cpp
    ../../deps/tapi/lib/Core/XPISet.cpp
    ../../deps/tapi/lib/Core/YAMLReaderWriter.cpp
    ../../deps/tapi/lib/Driver/Diagnostics.cpp
    ../../deps/tapi/lib/Driver/DriverOptions.cpp
    ../../deps/tapi/lib/Driver/Options.cpp
    ../../deps/tapi/lib/Driver/Snapshot.cpp
    ../../deps/tapi/lib/Driver/SnapshotFileSystem.cpp)

add_library (tapi SHARED ${TAPI_SOURCES})
add_prep_dep (tapi)

target_compile_definitions (tapi PRIVATE TAPI_PORT PATH_MAX=_MAX_PATH)

target_include_directories (tapi PRIVATE
    ../../deps/tapi/include
    "${CMAKE_CURRENT_BINARY_DIR}/include") # Headers generated with tblgens.

target_link_libraries (tapi PRIVATE ${CLANG_LIBS} ${LLVM_LIBS}
    # TODO: We should use original Clang + `lld-link`, this is just a simpler
    # workaround for #12.
    -fuse-ld=link
    # `link.exe` complains otherwise.
    -Wl,/nodefaultlib:libcmt)

## Tablegenning
set (INC1
    "${CMAKE_CURRENT_BINARY_DIR}/include/tapi/Driver/DiagnosticTAPIKinds.inc")
set (INC2 "${CMAKE_CURRENT_BINARY_DIR}/include/tapi/Driver/TAPIOptions.inc")

### Let `.cpp` files depend on generated `.inc` files.
get_target_property (srcs tapi SOURCES)
set_source_files_properties (${srcs}
    PROPERTIES OBJECT_DEPENDS "${INC1};${INC2}")

### Let CMake know how to generate `.inc` files.
add_custom_command (
    OUTPUT include/tapi/Driver/DiagnosticTAPIKinds.inc
    COMMAND "${CLANG_CMAKE_DIR}/bin/clang-tblgen.exe" "-o=${INC1}"
        -gen-clang-diags-defs
        "${SOURCE_DIR}/deps/tapi/include/tapi/Driver/DiagnosticTAPIKinds.td"
    DEPENDS "${CLANG_CMAKE_DIR}/bin/clang-tblgen.exe"
        "${SOURCE_DIR}/deps/tapi/include/tapi/Driver/DiagnosticTAPIKinds.td")
#### TODO: This also depends on some headers (in `deps/llvm/include`)...
add_custom_command (
    OUTPUT include/tapi/Driver/TAPIOptions.inc
    COMMAND "${CLANG_CMAKE_DIR}/bin/llvm-tblgen.exe" "-o=${INC2}"
        "-I=${SOURCE_DIR}/deps/llvm/include" -gen-opt-parser-defs
        "${SOURCE_DIR}/deps/tapi/include/tapi/Driver/TAPIOptions.td"
    DEPENDS "${CLANG_CMAKE_DIR}/bin/llvm-tblgen.exe"
        "${SOURCE_DIR}/deps/tapi/include/tapi/Driver/TAPIOptions.td")

### Let CMake know how to generate tblgens.
add_custom_target (config-clang-x86-Release
    COMMAND ninja config-clang-x86-Release
    WORKING_DIRECTORY "${BINARY_DIR}"
    USES_TERMINAL)
add_custom_command (
    OUTPUT "${CLANG_CMAKE_DIR}/bin/clang-tblgen.exe"
    COMMAND ninja clang-tblgen
    WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
    USES_TERMINAL
    DEPENDS config-clang-x86-Release)
add_custom_command (
    OUTPUT "${CLANG_CMAKE_DIR}/bin/llvm-tblgen.exe"
    COMMAND ninja llvm-tblgen
    WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
    USES_TERMINAL
    DEPENDS config-clang-x86-Release)
