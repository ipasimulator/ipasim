project (RTObjCInterop)

add_library (RTObjCInterop SHARED
    dllmain.cpp
    InteropBase.mm
    ObjCHelpers.mm
    RTHelpers.mm
    RTObject.mm)
