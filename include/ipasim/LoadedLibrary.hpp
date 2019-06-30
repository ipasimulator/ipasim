// LoadedLibrary.hpp: Definition of class `LoadedLibrary` and its descendants.

#ifndef IPASIM_LOADED_LIBRARY_HPP
#define IPASIM_LOADED_LIBRARY_HPP

#include "ipasim/Common.hpp"
#include "ipasim/Logger.hpp"
#include "ipasim/MachO.hpp"

#include <LIEF/LIEF.hpp>
#include <Windows.h>
#include <cassert>

namespace ipasim {

class DynamicLoader;

// Iterator over symbols of LIEF's Mach-O binary filtered by a RVA.
class DylibSymbolIterator {
public:
  DylibSymbolIterator(uint64_t RVA, LIEF::MachO::it_exported_symbols Symbols)
      : RVA(RVA), Symbols(std::move(Symbols)) {}

  DylibSymbolIterator begin();
  DylibSymbolIterator end() { return DylibSymbolIterator(RVA, Symbols.end()); }
  DylibSymbolIterator &next();
  DylibSymbolIterator IPASIM_PREFIX(++);
  bool operator!=(const DylibSymbolIterator &Other);
  LIEF::MachO::Symbol &operator*();

private:
  uint64_t RVA;
  LIEF::MachO::it_exported_symbols Symbols;
};

// Represents a dynamic library (or executable) loaded by `DynamicLoader`.
class LoadedLibrary {
public:
  LoadedLibrary() : StartAddress(0), Size(0), IsWrapper(false) {}
  virtual ~LoadedLibrary() = default;

  uint64_t StartAddress, Size;
  bool IsWrapper;

  virtual bool isDylib() = 0;
  bool isDLL() { return !isDylib(); }
  // TODO: Check that the found symbol is inside range [StartAddress, +Size].
  virtual uint64_t findSymbol(DynamicLoader &DL, const std::string &Name) = 0;
  virtual bool hasUnderscorePrefix() = 0;
  bool isInRange(uint64_t Addr);
  void checkInRange(uint64_t Addr);
  virtual bool hasMachO() = 0;
  virtual MachO getMachO() = 0;
};

// A `.dylib` loaded via library LIEF.
class LoadedDylib : public LoadedLibrary {
public:
  LIEF::MachO::Binary &Bin;

  LoadedDylib(std::unique_ptr<LIEF::MachO::FatBinary> &&Fat)
      : Fat(move(Fat)), Bin(Fat->at(0)), Header(0) {}

  bool isDylib() override { return true; }
  uint64_t findSymbol(DynamicLoader &DL, const std::string &Name) override;
  // TODO: Use this function to implement `src/objc/dladdr.mm`.
  DylibSymbolIterator lookup(uint64_t Addr);
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

// A `.dll` loaded via Windows API.
class LoadedDll : public LoadedLibrary {
public:
  HMODULE Ptr;
  bool MachOPoser;

  bool isDylib() override { return false; }
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
