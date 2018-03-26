#ifndef _H_OBJC_RUNTIME
#define _H_OBJC_RUNTIME

#include <stdint.h> // for int types

class objc_class;
class objc_object;

using Class = objc_class * ;
using id = objc_object * ;
using SEL = struct objc_selector *;
using IMP = void(*)(void /* id, SEL, ... */);

union isa_t
{
    isa_t() {}
    isa_t(uintptr_t value) : bits(value) {}

    Class cls;
    uintptr_t bits;
};

class objc_object {
private:
    isa_t isa;
};

class method_t {
public:
    SEL name;
    const char *types;
    IMP imp;
};

class ivar_t {
public:
    int32_t * offset;
    const char *name;
    const char *type;
    uint32_t alignment_raw;
    uint32_t size;
};

class property_t {
public:
    const char *name;
    const char *attributes;
};

template <typename Element, typename List, uint32_t FlagMask>
class entsize_list_tt {
public:
    uint32_t entsizeAndFlags;
    uint32_t count;
    Element first;
};

class method_list_t : public entsize_list_tt<method_t, method_list_t, 0x3> {};

class ivar_list_t : public entsize_list_tt<ivar_t, ivar_list_t, 0> {};

class property_list_t : public entsize_list_tt<property_t, property_list_t, 0> {};

class protocol_t : public objc_object {
public:
    const char *mangledName;
    class protocol_list_t *protocols;
    method_list_t *instanceMethods;
    method_list_t *classMethods;
    method_list_t *optionalInstanceMethods;
    method_list_t *optionalClassMethods;
    property_list_t *instanceProperties;
    uint32_t size;
    uint32_t flags;
    const char **_extendedMethodTypes;
    const char *_demangledName;
    property_list_t *_classProperties;
};

using protocol_ref_t = uintptr_t;

class protocol_list_t {
public:
    uintptr_t count;
    protocol_ref_t list[0];
};

template <typename Element, typename List>
class list_array_tt {
private:
    struct array_t {
        uint32_t count;
        List* lists[0];

        static size_t byteSize(uint32_t count) {
            return sizeof(array_t) + count * sizeof(lists[0]);
        }
        size_t byteSize() {
            return byteSize(count);
        }
    };

    union {
        List* list;
        uintptr_t arrayAndFlag;
    };
};

class method_array_t : public list_array_tt<method_t, method_list_t> {};

class property_array_t : public list_array_tt<property_t, property_list_t> {};

class class_ro_t {
public:
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    const uint8_t *ivarLayout;
    const char *name;
    method_list_t *baseMethodList;
    protocol_list_t *baseProtocols;
    const ivar_list_t *ivars;
    const uint8_t *weakIvarLayout;
    property_list_t *baseProperties;
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
    uintptr_t bits;
};

class objc_class : public objc_object {
private:
    Class superclass;
    uint64_t cache; // TODO: Wrong type.
};

#endif
