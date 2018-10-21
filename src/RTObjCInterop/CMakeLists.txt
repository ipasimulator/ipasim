project (RTObjCInterop)

# add_library (RTObjCInterop SHARED
#     dllmain.cpp
#     InteropBase.mm
#     ObjCHelpers.mm
#     RTHelpers.mm
#     RTObject.mm)

add_custom_target (RTObjCInterop
    DEPENDS clang
    COMMAND "${CLANG_INSTALL_DIR}/clang.exe" -fsyntax-only InteropBase.mm)
