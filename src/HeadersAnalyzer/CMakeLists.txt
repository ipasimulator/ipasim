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

target_compile_definitions (tapi PRIVATE TAPI_PORT PATH_MAX=_MAX_PATH)

target_include_directories (tapi PRIVATE
    ../../deps/tapi/include
    "${BINARY_DIR}/include" # Headers generated with tblgens.
    # TODO: Add these with `target_link_libraries`.
    ../../deps/llvm/include
    "${CLANG_CMAKE_DIR}/include"
    ../../deps/clang/include
    "${CLANG_CMAKE_DIR}/tools/clang/include")

# TODO: Only actually invoke the commands when necessary.
add_custom_target (tapi-tblgen
    # TODO: Wrong kind of dependency.
    # DEPENDS "${SOURCE_DIR}/deps/tapi/include/tapi/Driver/DiagnosticTAPIKinds.inc"
    # TODO: Add tblgen as a dependency.
    COMMAND "${CMAKE_COMMAND}" -E make_directory
        "${BINARY_DIR}/include/tapi/Driver"
    COMMAND "${CLANG_CMAKE_DIR}/bin/clang-tblgen.exe"
        "-o=${BINARY_DIR}/include/tapi/Driver/DiagnosticTAPIKinds.inc"
        -gen-clang-diags-defs
        "${SOURCE_DIR}/deps/tapi/include/tapi/Driver/DiagnosticTAPIKinds.td"
    COMMAND "${CLANG_CMAKE_DIR}/bin/llvm-tblgen.exe"
        "-o=${BINARY_DIR}/include/tapi/Driver/TAPIOptions.inc"
        "-I=${SOURCE_DIR}/deps/llvm/include" -gen-opt-parser-defs
        "${SOURCE_DIR}/deps/tapi/include/tapi/Driver/TAPIOptions.td"
    USES_TERMINAL
)

add_dependencies (tapi tapi-tblgen)
