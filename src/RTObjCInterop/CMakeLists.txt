project (RTObjCInterop)

set (SOURCE_FILES
    dllmain.cpp
    InteropBase.mm
    ObjCHelpers.mm
    RTHelpers.mm
    RTObject.mm)

add_library (RTObjCInterop SHARED ${SOURCE_FILES})

# add_custom_target (RTObjCInterop
#     DEPENDS clang
#     COMMAND "${CLANG_EXE}" -fsyntax-only InteropBase.mm)
