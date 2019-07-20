# This script is used by `scripts/CommonVariables.cmake`. See i13.

list (APPEND CMAKE_MODULE_PATH "${SOURCE_DIR}/scripts")
include (CommonVariables)

list (TRANSFORM CF_PUBLIC_HEADERS PREPEND
    "${SOURCE_DIR}/deps/WinObjC/Frameworks/CoreFoundation/")
list (TRANSFORM CF_PRIVATE_HEADERS PREPEND
    "${SOURCE_DIR}/deps/WinObjC/Frameworks/CoreFoundation/")

file (COPY ${CF_PUBLIC_HEADERS}
    DESTINATION "${SOURCE_DIR}/deps/WinObjC/include/CoreFoundation")
file (COPY ${CF_PRIVATE_HEADERS}
    DESTINATION "${SOURCE_DIR}/deps/WinObjC/Frameworks/include")
