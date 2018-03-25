#ifndef _H_OBJC_RUNTIME
#define _H_OBJC_RUNTIME

#include <stdint.h> // for int types

class objc_class;
class objc_object;

using Class = objc_class * ;
using id = objc_object * ;

union isa_t
{
    isa_t() {}
    isa_t(uintptr_t value) : bits(value) {}

    Class cls;
    uintptr_t bits;
};

class objc_object {
private:
    isa_t isa_;
};

class class_ro_t {
public:
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    const uint8_t *ivarLayout;
    const char *name;
    uintptr_t baseMethodList; // TODO: Wrong type.
    uintptr_t baseProtocols; // TODO: Wrong type.
    uintptr_t ivars; // TODO: Wrong type.
    const uint8_t *weakIvarLayout;
    uintptr_t baseProperties; // TODO: Wrong type.
};

class class_rw_t {
public:
    uint32_t flags;
    uint32_t version;
    const class_ro_t *ro;
    uintptr_t methods; // TODO: Wrong type.
    uintptr_t properties; // TODO: Wrong type.
    uintptr_t protocols; // TODO: Wrong type.
    Class firstSubclass;
    Class nextSiblingClass;
    char *demangledName;
};

class class_data_bits_t {
private:
    uintptr_t bits_;
};

class objc_class : objc_object {
private:
    Class superclass_;
    uint64_t cache_; // TODO: Wrong type.
};

#endif
