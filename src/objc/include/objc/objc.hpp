#ifndef OBJC_OBJC_H
#define OBJC_OBJC_H

#include "objc/runtime.hpp" // for SEL

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

/**
* [Apple] Registers a method with the Objective-C runtime system, maps the method
* [Apple] name to a selector, and returns the selector value.
* [Apple] 
* [Apple] @param str A pointer to a C string. Pass the name of the method you wish to register.
* [Apple] 
* [Apple] @return A pointer of type SEL specifying the selector for the named method.
* [Apple] 
* [Apple] @note You must register a method name with the Objective-C runtime system to obtain the
* [Apple]  method’s selector before you can add the method to a class definition. If the method name
* [Apple]  has already been registered, this function simply returns the selector.
*/
OBJC_EXPORT SEL _Nonnull sel_registerName(const char * _Nonnull str)
	OBJC_AVAILABLE(10.0, 2.0, 9.0, 1.0, 2.0);

#endif // OBJC_OBJC_H
