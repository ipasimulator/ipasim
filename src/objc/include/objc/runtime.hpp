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
#if __x86_64__
    // [Apple] *offset was originally 64-bit on some x86_64 platforms.
    // [Apple] We read and write only 32 bits of it.
    // [Apple] Some metadata provides all 64 bits. This is harmless for unsigned 
    // [Apple] little-endian values.
    // [Apple] Some code uses all 64 bits. class_addIvar() over-allocates the 
    // [Apple] offset for their benefit.
#endif
    int32_t * offset;
    const char *name;
    const char *type;
    // [Apple] alignment is sometimes -1. Use alignment() instead.
    uint32_t alignment_raw;
    uint32_t size;
};

class property_t {
public:
    const char *name;
    const char *attributes;
};

/***********************************************************************
* [Apple] entsize_list_tt<Element, List, FlagMask>
* [Apple] Generic implementation of an array of non-fragile structs.
* [Apple] 
* [Apple] Element is the struct type (e.g. method_t)
* [Apple] List is the specialization of entsize_list_tt (e.g. method_list_t)
* [Apple] FlagMask is used to stash extra bits in the entsize field
* [Apple]   (e.g. method list fixup markers)
**********************************************************************/
template <typename Element, typename List, uint32_t FlagMask>
class entsize_list_tt {
public:
    uint32_t entsizeAndFlags;
    uint32_t count;
    Element first;
};

// [Apple] Two bits of entsize are used for fixup markers.
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
    uint32_t size; // [Apple] sizeof(protocol_t)
    uint32_t flags;
    // [Apple] Fields below this point are not always present on disk.
    const char **_extendedMethodTypes;
    const char *_demangledName;
    property_list_t *_classProperties;
};

using protocol_ref_t = uintptr_t; // [Apple] protocol_t *, but unremapped

class protocol_list_t {
public:
    // [Apple] count is 64-bit by accident. 
    uintptr_t count;
    protocol_ref_t list[0]; // [Apple] variable-size
};

/***********************************************************************
* [Apple] list_array_tt<Element, List>
* [Apple] Generic implementation for metadata that can be augmented by categories.
* [Apple] 
* [Apple] Element is the underlying metadata type (e.g. method_t)
* [Apple] List is the metadata's list type (e.g. method_list_t)
* [Apple] 
* [Apple] A list_array_tt has one of three values:
* [Apple] - empty
* [Apple] - a pointer to a single list
* [Apple] - an array of pointers to lists
* [Apple] 
* [Apple] countLists/beginLists/endLists iterate the metadata lists
* [Apple] count/begin/end iterate the underlying metadata elements
**********************************************************************/
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

class protocol_array_t : public list_array_tt<protocol_ref_t, protocol_list_t> {};

class class_ro_t {
public:
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
#ifdef __LP64__
    uint32_t reserved;
#endif
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
    // [Apple] Be warned that Symbolication knows the layout of this structure.
    uint32_t flags;
    uint32_t version;
    const class_ro_t *ro;
    method_array_t methods;
    property_array_t properties;
    protocol_array_t protocols;
    Class firstSubclass;
    Class nextSiblingClass;
    char *demangledName;
};

class class_data_bits_t {
private:
    // [Apple] Values are the FAST_ flags above.
    uintptr_t bits;
};

#if __LP64__
using mask_t = uint32_t; // [Apple] x86_64 & arm64 asm are less efficient with 16-bits
#else
using mask_t = uint16_t;
#endif

using cache_key_t = uintptr_t;

class bucket_t {
private:
    cache_key_t _key;
    IMP _imp;
};

class cache_t {
public:
    bucket_t *_buckets;
    mask_t _mask;
    mask_t _occupied;
};

class objc_class : public objc_object {
private:
    // [Apple] Class ISA;
    Class superclass;
    cache_t cache; // [Apple] formerly cache pointer and vtable
    class_data_bits_t bits; // [Apple] class_rw_t * plus custom rr/alloc flags
};

#endif
