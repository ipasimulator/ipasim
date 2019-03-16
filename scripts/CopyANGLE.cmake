# This script is used by `src/IpaSimulator/CMakeLists.txt`.

list (APPEND CMAKE_MODULE_PATH "${SOURCE_DIR}/scripts")
include (CommonVariables)

file (
    COPY "${ANGLE_DIR}/bin/UAP/Win32/libEGL.dll"
        "${ANGLE_DIR}/bin/UAP/Win32/libGLESv2.dll"
    DESTINATION "${IPASIM_CMAKE_DIR}/bin")
