list (APPEND CMAKE_MODULE_PATH "${SOURCE_DIR}/scripts")
include (CommonVariables)

file (MAKE_DIRECTORY "${LIBFFI_CMAKE_DIR}")
execute_process (
    COMMAND "${CMAKE_COMMAND}" -G Ninja
        -DCMAKE_BUILD_TYPE=Debug
        -DCMAKE_EXPORT_COMPILE_COMMANDS=On
        "${SOURCE_DIR}/deps/Libffi"
    WORKING_DIRECTORY "${LIBFFI_CMAKE_DIR}")
