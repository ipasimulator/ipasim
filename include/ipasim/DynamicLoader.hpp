// DynamicLoader.hpp

#ifndef IPASIM_DYNAMIC_LOADER_HPP
#define IPASIM_DYNAMIC_LOADER_HPP

#include "ipasim/Common.hpp"
#include "ipasim/Emulator.hpp"
#include "ipasim/LoadedLibrary.hpp"
#include "ipasim/Logger.hpp"

#include <functional>
#include <map>
#include <stack>
#include <string>
#include <unicorn/unicorn.h>

namespace ipasim {

struct BinaryPath {
  std::string Path;
  bool Relative; // true iff `Path` is relative to install dir

  bool isFileValid() const;
};

struct AddrInfo {
  const std::string *LibPath;
  LoadedLibrary *Lib;
  std::string SymbolName;
};

class DynamicLoader {
public:
  DynamicLoader(Emulator &Emu);
  LoadedLibrary *load(const std::string &Path);
  // Finds only library, no symbol information is inspected. To do that, call
  // `inspect`.
  AddrInfo lookup(uint64_t Addr);
  AddrInfo inspect(uint64_t Addr);
  DebugStream::Handler dumpAddr(uint64_t Addr);
  DebugStream::Handler dumpAddr(uint64_t Addr, const AddrInfo &AI);
  uint64_t getKernelAddr() { return KernelAddr; }
  static constexpr uint64_t alignToPageSize(uint64_t Addr) {
    return Addr & (-PageSize);
  }
  static constexpr uint64_t roundToPageSize(uint64_t Addr) {
    return alignToPageSize(Addr + PageSize - 1);
  }

  static constexpr int PageSize = 4096;

private:
  bool canSegmentsSlide(LIEF::MachO::Binary &Bin);
  BinaryPath resolvePath(const std::string &Path);
  LoadedLibrary *loadMachO(const std::string &Path);
  LoadedLibrary *loadPE(const std::string &Path);

  static constexpr int R_SCATTERED = 0x80000000; // From `<mach-o/reloc.h>`.
  Emulator &Emu;
  uint64_t KernelAddr;
  std::map<std::string, std::unique_ptr<LoadedLibrary>> LLs;
};

} // namespace ipasim

// !defined(IPASIM_DYNAMIC_LOADER_HPP)
#endif
