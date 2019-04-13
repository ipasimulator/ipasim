// LoadedLibrary.hpp

#ifndef IPASIM_LOADED_LIBRARY_HPP
#define IPASIM_LOADED_LIBRARY_HPP

#include <LIEF/LIEF.hpp>
#include <Windows.h>
#include <cassert>

namespace ipasim {

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

private:
  const void *Hdr;
};

class DynamicLoader;

class LoadedLibrary {
public:
  LoadedLibrary() : StartAddress(0), Size(0), IsWrapperDLL(false) {}
  virtual ~LoadedLibrary() = default;

  uint64_t StartAddress, Size;
  bool IsWrapperDLL;

  // TODO: Check that the found symbol is inside range [StartAddress, +Size].
  virtual uint64_t findSymbol(DynamicLoader &DL, const std::string &Name) = 0;
  virtual bool hasUnderscorePrefix() = 0;
  bool isInRange(uint64_t Addr);
  void checkInRange(uint64_t Addr);
  const char *getMethodType(uint64_t Addr);
  const char *getClassOfMethod(uint64_t Addr);
  virtual bool hasMachO() = 0;
  virtual MachO getMachO() = 0;

private:
  const char *getClassOfMethod(const char *Section, uint64_t Addr);
};

class LoadedDylib : public LoadedLibrary {
public:
  LIEF::MachO::Binary &Bin;

  LoadedDylib(std::unique_ptr<LIEF::MachO::FatBinary> &&Fat)
      : Fat(move(Fat)), Bin(Fat->at(0)), Header(0) {}
  uint64_t findSymbol(DynamicLoader &DL, const std::string &Name) override;
  bool hasUnderscorePrefix() override { return true; }
  bool hasMachO() override { return true; }
  MachO getMachO() override {
    if (!Header)
      Header = StartAddress + Bin.imagebase();
    return MachO(reinterpret_cast<const void *>(Header));
  }

private:
  std::unique_ptr<LIEF::MachO::FatBinary> Fat;
  uint64_t Header;
};

class LoadedDll : public LoadedLibrary {
public:
  HMODULE Ptr;
  bool MachOPoser;

  uint64_t findSymbol(DynamicLoader &DL, const std::string &Name) override;
  bool hasUnderscorePrefix() override { return false; }
  bool hasMachO() override { return MachOPoser; }
  MachO getMachO() override {
    assert(hasMachO());
    return MachO(reinterpret_cast<const void *>(StartAddress));
  }
};

} // namespace ipasim

// !defined(IPASIM_LOADED_LIBRARY_HPP)
#endif
