#ifndef _H_OBJC_OBJC
#define _H_OBJC_OBJC

#include "objc/runtime.hpp"

// TODO: Move these macro definitions to some api.hpp file as Apple does.
#define OBJC_EXPORT extern "C" __declspec(dllexport)
#define _Nonnull /* TODO: Empty for now. */
#define OBJC_AVAILABLE(x, i, t, w, b) /* TODO: Empty for now. */

/**
* [Apple] Returns the name of the method specified by a given selector.
* [Apple] 
* [Apple] @param sel A pointer of type \c SEL. Pass the selector whose name you wish to determine.
* [Apple] 
* [Apple] @return A C string indicating the name of the selector.
*/
OBJC_EXPORT const char * _Nonnull sel_getName(SEL _Nonnull sel)
	OBJC_AVAILABLE(10.0, 2.0, 9.0, 1.0, 2.0);

#endif // _H_OBJC_OBJC
