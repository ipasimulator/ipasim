# LLVM libraries
add_custom_target (config-clang-x86-Debug
    COMMENT "Configure LLVM libs"
    COMMAND ninja config-clang-x86-Debug
    WORKING_DIRECTORY "${BINARY_DIR}"
    USES_TERMINAL)
function (add_clang_libs title names include_dirs tablegen_targets)
    # Create include directories as some of them might be filled with generated
    # headers at build time, but CMake would complain at configure time that
    # those directories don't exist.
    file (MAKE_DIRECTORY ${include_dirs})

    foreach (name ${names})
        # Add imported library `${name}.lib`.
        add_library ("${name}" STATIC IMPORTED)
        set_target_properties ("${name}" PROPERTIES
            IMPORTED_LOCATION "${DEBUG_CLANG_CMAKE_DIR}/lib/${name}.lib")
        target_compile_definitions ("${name}" INTERFACE _DEBUG _MT _DLL)
        target_link_libraries ("${name}" INTERFACE
            ucrtd vcruntimed msvcrtd msvcprtd)
        target_include_directories ("${name}" INTERFACE ${include_dirs})
        if (tablegen_targets)
            add_dependencies ("${name}" ${tablegen_targets})
        endif (tablegen_targets)
    endforeach (name)

    # Let CMake know how to generate those `.lib`s.
    set (libs ${names})
    list (TRANSFORM libs PREPEND "${DEBUG_CLANG_CMAKE_DIR}/lib/")
    list (TRANSFORM libs APPEND .lib)
    add_custom_target ("gen-${title}"
        COMMENT "Generate ${title} libs"
        BYPRODUCTS ${libs}
        COMMAND ninja ${names}
        WORKING_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}"
        USES_TERMINAL
        DEPENDS config-clang-x86-Debug)
endfunction (add_clang_libs)

set (LLDB_LIBS
    liblldb
    lldbBase
    lldbBreakpoint
    lldbCommands
    lldbCore
    lldbDataFormatters
    lldbExpression
    lldbHost
    lldbInitialization
    lldbInterpreter
    lldbPluginABIMacOSX_arm
    lldbPluginABIMacOSX_arm64
    lldbPluginABIMacOSX_i386
    lldbPluginABISysV_arm
    lldbPluginABISysV_arm64
    lldbPluginABISysV_hexagon
    lldbPluginABISysV_i386
    lldbPluginABISysV_mips
    lldbPluginABISysV_mips64
    lldbPluginABISysV_ppc
    lldbPluginABISysV_ppc64
    lldbPluginABISysV_s390x
    lldbPluginABISysV_x86_64
    lldbPluginAppleObjCRuntime
    lldbPluginArchitectureArm
    lldbPluginArchitecturePPC64
    lldbPluginCPlusPlusLanguage
    lldbPluginCXXItaniumABI
    lldbPluginDisassemblerLLVM
    lldbPluginDynamicLoaderHexagonDYLD
    lldbPluginDynamicLoaderMacOSXDYLD
    lldbPluginDynamicLoaderPosixDYLD
    lldbPluginDynamicLoaderStatic
    lldbPluginDynamicLoaderWindowsDYLD
    lldbPluginExpressionParserClang
    lldbPluginExpressionParserGo
    lldbPluginGoLanguage
    lldbPluginInstructionARM
    lldbPluginInstructionARM64
    lldbPluginInstructionMIPS
    lldbPluginInstructionMIPS64
    lldbPluginInstructionPPC64
    lldbPluginInstrumentationRuntimeASan
    lldbPluginInstrumentationRuntimeMainThreadChecker
    lldbPluginInstrumentationRuntimeTSan
    lldbPluginInstrumentationRuntimeUBSan
    lldbPluginJavaLanguage
    lldbPluginJITLoaderGDB
    lldbPluginLanguageRuntimeGo
    lldbPluginLanguageRuntimeJava
    lldbPluginMemoryHistoryASan
    lldbPluginObjCLanguage
    lldbPluginObjCPlusPlusLanguage
    lldbPluginObjectContainerBSDArchive
    lldbPluginObjectContainerMachOArchive
    lldbPluginObjectFileELF
    lldbPluginObjectFileJIT
    lldbPluginObjectFileMachO
    lldbPluginObjectFilePECOFF
    lldbPluginOCamlLanguage
    lldbPluginOSGo
    lldbPluginOSPython
    lldbPluginPlatformAndroid
    lldbPluginPlatformFreeBSD
    lldbPluginPlatformGDB
    lldbPluginPlatformKalimba
    lldbPluginPlatformLinux
    lldbPluginPlatformMacOSX
    lldbPluginPlatformNetBSD
    lldbPluginPlatformOpenBSD
    lldbPluginPlatformPOSIX
    lldbPluginPlatformWindows
    lldbPluginProcessElfCore
    lldbPluginProcessGDBRemote
    lldbPluginProcessMinidump
    lldbPluginProcessUtility
    lldbPluginProcessWindowsCommon
    lldbPluginRenderScriptRuntime
    lldbPluginScriptInterpreterNone
    lldbPluginScriptInterpreterPython
    lldbPluginStructuredDataDarwinLog
    lldbPluginSymbolFileDWARF
    lldbPluginSymbolFilePDB
    lldbPluginSymbolFileSymtab
    lldbPluginSymbolVendorELF
    lldbPluginSystemRuntimeMacOSX
    lldbPluginUnwindAssemblyInstEmulation
    lldbPluginUnwindAssemblyX86
    lldbSymbol
    lldbTarget
    lldbUtility)

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
    LLVMARMAsmParser
    LLVMARMAsmPrinter
    LLVMARMCodeGen
    LLVMARMDesc
    LLVMARMDisassembler
    LLVMARMInfo
    LLVMARMUtils
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

## These targets generate LLVM headers. Note that these are only tablegenned
## headers. Other generated headers, like `config.h`, are generated at configure
## time.
add_custom_target (clang-tablegen-targets
    COMMENT "Clang tablegen targets"
    COMMAND ninja clang-tablegen-targets
    WORKING_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}"
    USES_TERMINAL
    DEPENDS config-clang-x86-Debug)
set (LLVM_TABLEGEN_TARGETS
    intrinsics_gen
    AttributeCompatFuncTableGen
    COFFOptionsTableGen
    CvtResTableGen
    DllOptionsTableGen
    DriverOptionsTableGen
    ELFOptionsTableGen
    LibOptionsTableGen
    MinGWOptionsTableGen
    MtTableGen
    ObjcopyTableGen
    OptsTestTableGen
    RcTableGen
    WasmOptionsTableGen
    X86CommonTableGen)
add_custom_target (llvm-tablegen-targets
    COMMENT "LLVM tablegen targets"
    COMMAND ninja ${LLVM_TABLEGEN_TARGETS}
    WORKING_DIRECTORY "${DEBUG_CLANG_CMAKE_DIR}"
    USES_TERMINAL
    DEPENDS config-clang-x86-Debug)

set (LLDB_INCLUDE_DIRS
    "${DEBUG_CLANG_CMAKE_DIR}/tools/lldb/include"
    "${SOURCE_DIR}/deps/lldb/include")
set (CLANG_INCLUDE_DIRS
    "${DEBUG_CLANG_CMAKE_DIR}/tools/clang/include"
    "${SOURCE_DIR}/deps/clang/include")
set (LLVM_INCLUDE_DIRS
    "${DEBUG_CLANG_CMAKE_DIR}/include"
    "${SOURCE_DIR}/deps/llvm/include")

add_clang_libs (LLDB "${LLDB_LIBS}" "${LLDB_INCLUDE_DIRS}" "")
add_clang_libs (Clang "${CLANG_LIBS}" "${CLANG_INCLUDE_DIRS}"
    clang-tablegen-targets)
add_clang_libs (LLVM "${LLVM_LIBS}" "${LLVM_INCLUDE_DIRS}"
    llvm-tablegen-targets)

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

# Making `tapi` `SHARED` doesn't work due to unresolved symbols in
# `HeadersAnalyzer.exe`.
add_library (tapi STATIC ${TAPI_SOURCES})
add_prep_dep (tapi) # TODO: Use original Clang for CodeGen. See also #12.

target_compile_definitions (tapi PRIVATE TAPI_PORT PATH_MAX=_MAX_PATH)

target_include_directories (tapi PUBLIC
    "${CMAKE_CURRENT_BINARY_DIR}/include" # Headers generated with tblgens.
    ../../deps/tapi/include)

target_link_libraries (tapi PRIVATE ${CLANG_LIBS} ${LLVM_LIBS})

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
    COMMENT "Configure LLVM tablegens"
    COMMAND ninja config-clang-x86-Release
    WORKING_DIRECTORY "${BINARY_DIR}"
    USES_TERMINAL)
add_custom_target (gen-clang-tblgen
    COMMENT "Generate Clang tablegen"
    BYPRODUCTS "${CLANG_CMAKE_DIR}/bin/clang-tblgen.exe"
    COMMAND ninja clang-tblgen
    WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
    USES_TERMINAL
    DEPENDS config-clang-x86-Release)
add_custom_target (gen-llvm-tblgen
    COMMENT "Generate LLVM tablegen"
    BYPRODUCTS "${CLANG_CMAKE_DIR}/bin/llvm-tblgen.exe"
    COMMAND ninja llvm-tblgen
    WORKING_DIRECTORY "${CLANG_CMAKE_DIR}"
    USES_TERMINAL
    DEPENDS config-clang-x86-Release)

# DIA SDK
add_library (dia SHARED IMPORTED)
set_target_properties (dia PROPERTIES
    IMPORTED_LOCATION "C:/BuildTools/DIA SDK/bin/msdia140.dll"
    IMPORTED_IMPLIB "C:/BuildTools/DIA SDK/lib/diaguids.lib")

# HeadersAnalyzer
set (SOURCE_FILES
    ClangHelper.cpp
    Common.cpp
    ErrorReporting.cpp
    HAContext.cpp
    HeadersAnalyzer.cpp
    LLDBHelper.cpp
    LLVMHelper.cpp
    TapiHelper.cpp)

add_executable (HeadersAnalyzer ${SOURCE_FILES})
add_prep_dep (HeadersAnalyzer) # TODO: Use original Clang for CodeGen.

target_compile_options (HeadersAnalyzer PRIVATE -std=c++17 -gcodeview)

target_include_directories (HeadersAnalyzer PRIVATE
    # Private Clang headers
    ../../deps/clang/lib
    # Private LLDB headers
    ../../deps/lldb/source)

target_link_libraries (HeadersAnalyzer PRIVATE
    ${LLDB_LIBS} ${CLANG_LIBS} ${LLVM_LIBS} tapi dia ws2_32.lib mincore.lib
    # TODO: We should use original Clang + `lld-link`, this is just a simpler
    # workaround for #12.
    -fuse-ld=link
    # `link.exe` complains otherwise.
    -Wl,/nodefaultlib:libcmt)

set (CG_OUTPUTS "${SOURCE_DIR}/src/HeadersAnalyzer/Debug/CG/exports.txt")
add_custom_command (OUTPUT ${CG_OUTPUTS}
    COMMENT "Code-gen"
    COMMAND "${IPASIM_CMAKE_DIR}/bin/HeadersAnalyzer.exe"
    WORKING_DIRECTORY "${SOURCE_DIR}"
    USES_TERMINAL
    DEPENDS HeadersAnalyzer)
add_custom_target (CodeGen
    DEPENDS ${CG_OUTPUTS})

# TODO: Clear the output directory `gen` before emitting binaries.
