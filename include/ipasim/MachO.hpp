// MachO.hpp

#ifndef IPASIM_MACHO_HPP
#define IPASIM_MACHO_HPP

#include "ipasim/Logger.hpp"

#include <cstdint>
#include <type_traits>

namespace ipasim {

class ObjCClass {
public:
  ObjCClass(void *Data) : Data(Data) {}

  const char *getName();

  operator bool() { return Data; }

private:
  void *Data;
};

class ObjCMethod {
public:
  ObjCMethod() : ClassData(nullptr), MethodData(nullptr) {}
  ObjCMethod(void *MethodData) : MethodData(MethodData) {}
  ObjCMethod(void *ClassData, void *MethodData)
      : ClassData(ClassData), MethodData(MethodData) {}

  ObjCClass getClass() { return ObjCClass(ClassData); }
  const char *getName();
  const char *getType();

  operator bool() { return MethodData; }

private:
  void *ClassData;
  void *MethodData;
};

template <typename StreamTy>
std::enable_if_t<is_stream_v<StreamTy>, StreamTy> &operator<<(StreamTy &Str,
                                                              ObjCMethod M) {
  if (ObjCClass C = M.getClass())
    return Str << "[" << C.getName() << " " << M.getName()
               << "]:" << M.getType();
  return Str << M.getName() << ":" << M.getType();
}

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
