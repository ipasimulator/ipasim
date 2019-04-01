// LoadedLibrary.hpp

#ifndef IPASIM_LOADED_LIBRARY_HPP
#define IPASIM_LOADED_LIBRARY_HPP

#include <LIEF/LIEF.hpp>
#include <Windows.h>

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
  const char *getMethodType(uint64_t Addr);
  const char *getClassOfMethod(uint64_t Addr);
  virtual uint64_t getSection(const std::string &Name,
                              uint64_t *Size = nullptr) = 0;
};

class LoadedDylib : public LoadedLibrary {
public:
  LIEF::MachO::Binary &Bin;

  LoadedDylib(std::unique_ptr<LIEF::MachO::FatBinary> &&Fat)
      : Fat(move(Fat)), Bin(Fat->at(0)) {}
  uint64_t findSymbol(DynamicLoader &DL, const std::string &Name) override;
  bool hasUnderscorePrefix() override { return true; }
  uint64_t getSection(const std::string &Name, uint64_t *Size) override;

private:
  std::unique_ptr<LIEF::MachO::FatBinary> Fat;
};

class LoadedDll : public LoadedLibrary {
public:
  HMODULE Ptr;
  bool MachOPoser;

  uint64_t findSymbol(DynamicLoader &DL, const std::string &Name) override;
  bool hasUnderscorePrefix() override { return false; }
  uint64_t getSection(const std::string &Name, uint64_t *Size) override;
};

} // namespace ipasim

// !defined(IPASIM_LOADED_LIBRARY_HPP)
#endif
