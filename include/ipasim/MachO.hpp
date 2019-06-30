// MachO.hpp: Definition of class `MachO` and related `ObjC*` classes.

#ifndef IPASIM_MACHO_HPP
#define IPASIM_MACHO_HPP

#include "ipasim/Logger.hpp"

#include <cstdint>
#include <type_traits>

namespace ipasim {

// Represents Objective-C class or category.
class ObjCClass {
public:
  ObjCClass() : Category(false), Data(nullptr) {}
  ObjCClass(bool Category, void *Data) : Category(Category), Data(Data) {}

  const char *getName();
  // Returns empty class if this instance doesn't represent a category.
  ObjCClass getCategoryClass();

  operator bool() { return Data; }

private:
  bool Category;
  void *Data;
};

// Represents Objective-C method.
class ObjCMethod {
public:
  ObjCMethod() : ClassData(nullptr), MethodData(nullptr) {}
  ObjCMethod(void *MethodData) : MethodData(MethodData) {}
  ObjCMethod(bool Category, void *ClassData, void *MethodData)
      : Category(Category), ClassData(ClassData), MethodData(MethodData) {}

  ObjCClass getClass() { return ObjCClass(Category, ClassData); }
  const char *getName();
  const char *getType();

  operator bool() { return MethodData; }

private:
  bool Category;
  void *ClassData;
  void *MethodData;
};

// Logs as much information about `ObjCMethod` as possible.
template <typename StreamTy>
std::enable_if_t<is_stream_v<StreamTy>, StreamTy> &operator<<(StreamTy &Str,
                                                              ObjCMethod M) {
  if (ObjCClass C = M.getClass()) {
    Str << "[";
    if (ObjCClass Cls = C.getCategoryClass())
      Str << Cls.getName() << "(" << C.getName() << ")";
    else
      Str << C.getName();
    Str << " " << M.getName() << "]:" << M.getType();
  } else
    Str << M.getName() << ":" << M.getType();
  return Str;
}

// Helper class for reading sections, especially Objective-C-related, by
// analyzing Mach-O headers. Note that the Mach-O binary being analyzed must be
// loaded in memory at runtime (cf. class `ObjCMethodScout`).
class MachO {
public:
  MachO(const void *Hdr) : Hdr(Hdr) {}

  static constexpr const char *DataSegment = "__DATA";

  template <typename T>
  const T *getSectionData(const char *SegName, const char *SectName,
                          size_t *Count = nullptr) {
    if (!Count)
      return reinterpret_cast<const T *>(getSection(SegName, SectName));

    uint64_t Size;
    auto *Result =
        reinterpret_cast<const T *>(getSection(SegName, SectName, &Size));
    *Count = Size / sizeof(T);
    return Result;
  }
  uint64_t getSection(const char *SegName, const char *SectName,
                      uint64_t *Size = nullptr);
  ObjCMethod findMethod(uint64_t Addr);

private:
  const void *Hdr;

  ObjCMethod findMethod(const char *Section, uint64_t Addr);
};

} // namespace ipasim

// !defined(IPASIM_MACHO_HPP)
#endif
