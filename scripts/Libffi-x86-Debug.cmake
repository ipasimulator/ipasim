list (APPEND CMAKE_MODULE_PATH "${SOURCE_DIR}/scripts")
include (CommonVariables)

file (MAKE_DIRECTORY "${DEBUG_LIBFFI_CMAKE_DIR}")
execute_process (
    COMMAND "${CMAKE_COMMAND}" -G Ninja
        -DCMAKE_BUILD_TYPE=Debug
        -DCMAKE_EXPORT_COMPILE_COMMANDS=On
        -DHAVE_64BIT=Off
        "${SOURCE_DIR}/deps/Libffi"
    WORKING_DIRECTORY "${DEBUG_LIBFFI_CMAKE_DIR}")
