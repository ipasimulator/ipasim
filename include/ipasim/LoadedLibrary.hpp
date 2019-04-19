// LoadedLibrary.hpp

#ifndef IPASIM_LOADED_LIBRARY_HPP
#define IPASIM_LOADED_LIBRARY_HPP

#include "ipasim/Logger.hpp"
#include "ipasim/MachO.hpp"

#include <LIEF/LIEF.hpp>
#include <Windows.h>
#include <cassert>

namespace ipasim {

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
  virtual bool hasMachO() = 0;
  virtual MachO getMachO() = 0;
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
