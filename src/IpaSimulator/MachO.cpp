// MachO.cpp: Implementation of class `MachO`.

#include "ipasim/MachO.hpp"

#include "ipasim/Common.hpp"

#include <llvm/BinaryFormat/MachO.h>

using namespace ipasim;

// Inspired by
// https://opensource.apple.com/source/cctools/cctools-895/libmacho/getsecbyname.c.auto.html.
uint64_t MachO::getSection(const char *SegName, const char *SectName,
                           uint64_t *Size) {
  using namespace llvm::MachO;

  // Enumerate segments.
  uint64_t Slide, Addr;
  bool HasSlide = false, HasAddr = false;
  auto HdrAddr = reinterpret_cast<uint64_t>(Hdr);
  auto *Header = reinterpret_cast<const mach_header *>(Hdr);
  auto *Cmd = reinterpret_cast<const load_command *>(Header + 1);
  for (size_t I = 0, IEnd = Header->ncmds; I != IEnd; ++I) {
    if (Cmd->cmd == LC_SEGMENT) {
      auto *Seg = reinterpret_cast<const segment_command *>(Cmd);

      // Look for segment `__TEXT` to compute slide. Note that section and
      // segment names are not necessarily null-terminated!
      if (!HasSlide && !strncmp(Seg->segname, "__TEXT", sizeof(Seg->segname))) {
        Slide = HdrAddr - Seg->vmaddr;
        HasSlide = true;
        if (HasAddr)
          break;
      }

      // Enumerate segment's sections.
      if (!HasAddr && !strncmp(Seg->segname, SegName, sizeof(Seg->segname))) {
        for (auto *Sect = reinterpret_cast<const section *>(Seg + 1),
                  *EndSect = Sect + Seg->nsects;
             Sect != EndSect; ++Sect)
          if (!strncmp(Sect->sectname, SectName, sizeof(Sect->sectname)) &&
              !strncmp(Sect->segname, SegName, sizeof(Sect->segname))) {
            // We have found it.
            if (Size)
              *Size = Sect->size;
            Addr = Sect->addr;
            HasAddr = true;
            if (HasSlide)
              break;
          }
      }
    }

    // Move to the next `load_command`.
    Cmd = reinterpret_cast<const load_command *>(bytes(Cmd) + Cmd->cmdsize);
  }

  if (HasSlide && HasAddr)
    return Addr + Slide;
  return 0;
}

namespace {

struct method_t {
  const char *name;
  const char *types;
  void *imp;
};

struct method_list_t {
  uint32_t entrysize;
  uint32_t count;
  method_t methods[0];
};

constexpr int FAST_DATA_MASK = 0xfffffffcUL;
constexpr int RW_REALIZED = 1 << 31;

struct class_ro_t {
  uint32_t flags;
  uint32_t instanceStart;
  uint32_t instanceSize;

  const uint8_t *ivarLayout;

  const char *name;
  method_list_t *baseMethodList;
  void *baseProtocols;
  const void *ivars;

  const uint8_t *weakIvarLayout;
  void *baseProperties;
};

template <typename Element, typename List> class list_array_tt {
  struct array_t {
    uint32_t count;
    List *lists[0];
  };

private:
  union {
    List *list;
    uintptr_t arrayAndFlag;
  };

  bool hasArray() const { return arrayAndFlag & 1; }
  array_t *array() { return (array_t *)(arrayAndFlag & ~1); }

public:
  List **beginLists() {
    if (hasArray()) {
      return array()->lists;
    } else {
      return &list;
    }
  }

  List **endLists() {
    if (hasArray()) {
      return array()->lists + array()->count;
    } else if (list) {
      return &list + 1;
    } else {
      return &list;
    }
  }
};

using method_array_t = list_array_tt<method_t, method_list_t>;

struct class_rw_t {
  uint32_t flags;
  uint32_t version;

  const class_ro_t *ro;

  method_array_t methods;
};

struct objc_class {
  objc_class *isa;
  void *superclass;
  void *cache;
  void *vtable;
  class_ro_t *info;

  class_rw_t *data() {
    return (class_rw_t *)((uintptr_t)info & FAST_DATA_MASK);
  }
  bool isRealized() { return data()->flags & RW_REALIZED; }
  const class_ro_t *getInfo() { return isRealized() ? data()->ro : info; }
};

struct category_t {
  const char *name;
  objc_class *cls;
  method_list_t *instanceMethods;
  method_list_t *classMethods;
};

} // namespace

const char *ObjCMethod::getName() {
  return reinterpret_cast<method_t *>(MethodData)->name;
}
const char *ObjCMethod::getType() {
  return reinterpret_cast<method_t *>(MethodData)->types;
}
const char *ObjCClass::getName() {
  if (Category)
    return reinterpret_cast<category_t *>(Data)->name;
  return reinterpret_cast<objc_class *>(Data)->getInfo()->name;
}
ObjCClass ObjCClass::getCategoryClass() {
  if (Category)
    return ObjCClass(/* Category */ false,
                     reinterpret_cast<category_t *>(Data)->cls);
  return ObjCClass();
}

static method_t *findMethodImpl(method_list_t *Methods, uint64_t Addr) {
  if (!Methods)
    return nullptr;
  for (size_t J = 0; J != Methods->count; ++J) {
    method_t &Method = Methods->methods[J];
    if (reinterpret_cast<uint64_t>(Method.imp) == Addr)
      return &Method;
  }
  return nullptr;
}

static method_t *findMethodImpl(objc_class *Class, uint64_t Addr) {
  if (method_t *M = findMethodImpl(Class->getInfo()->baseMethodList, Addr))
    return M;
  if (Class->isRealized())
    for (auto *L = Class->data()->methods.beginLists(),
              *End = Class->data()->methods.endLists();
         L != End; ++L)
      if (method_t *M = findMethodImpl(*L, Addr))
        return M;
  return nullptr;
}

ObjCMethod MachO::findMethod(const char *Section, uint64_t Addr) {
  size_t Count;
  if (auto *Classes =
          getSectionData<objc_class *>(MachO::DataSegment, Section, &Count))
    for (size_t I = 0; I != Count; ++I) {
      // Enumerate methods of every class and its meta-class.
      objc_class *Class = Classes[I];
      if (method_t *M = findMethodImpl(Class, Addr))
        return ObjCMethod(/* Category */ false, Class, M);
      if (method_t *M = findMethodImpl(Class->isa, Addr))
        return ObjCMethod(/* Category */ false, Class->isa, M);
    }
  return ObjCMethod();
}

ObjCMethod MachO::findMethod(uint64_t Addr) {
  // Enumerate classes in the image.
  if (ObjCMethod M = findMethod("__objc_classlist", Addr))
    return M;

  // Try also non-lazy classes.
  if (ObjCMethod M = findMethod("__objc_nlclslist", Addr))
    return M;

  // Try also categories.
  size_t Count;
  if (auto *Categories = getSectionData<category_t *>(MachO::DataSegment,
                                                      "__objc_catlist", &Count))
    for (size_t I = 0; I != Count; ++I) {
      // Enumerate methods of every category.
      category_t *Category = Categories[I];
      if (method_t *M = findMethodImpl(Category->classMethods, Addr))
        return ObjCMethod(/* Category */ true, Category, M);
      if (method_t *M = findMethodImpl(Category->instanceMethods, Addr))
        return ObjCMethod(/* Category */ true, Category, M);
    }

  return ObjCMethod();
}
