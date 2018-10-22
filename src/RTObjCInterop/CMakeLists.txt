project (RTObjCInterop)

set (SOURCE_FILES
    dllmain.cpp
    InteropBase.mm
    ObjCHelpers.mm
    RTHelpers.mm
    RTObject.mm)

add_library (RTObjCInterop SHARED ${SOURCE_FILES})

add_dependencies (RTObjCInterop clang)
