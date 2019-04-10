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
#include <vector>

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

using _dyld_objc_notify_mapped = void (*)(unsigned count,
                                          const char *const paths[],
                                          const void *const mh[]);
using _dyld_objc_notify_init = void (*)(const char *path, const void *mh);
using _dyld_objc_notify_unmapped = void (*)(const char *path, const void *mh);

class DynamicLoader {
public:
  DynamicLoader(Emulator &Emu);
  LoadedLibrary *load(const std::string &Path);
  void registerMachO(const void *Hdr);
  void registerHandler(_dyld_objc_notify_mapped Mapped,
                       _dyld_objc_notify_init Init,
                       _dyld_objc_notify_unmapped Unmapped);
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
  struct MachOHandler {
    _dyld_objc_notify_mapped Mapped;
    _dyld_objc_notify_init Init;
    _dyld_objc_notify_unmapped Unmapped;
  };

  bool canSegmentsSlide(LIEF::MachO::Binary &Bin);
  BinaryPath resolvePath(const std::string &Path);
  LoadedLibrary *loadMachO(const std::string &Path);
  LoadedLibrary *loadPE(const std::string &Path);
  void handleMachOs(size_t HdrOffset, size_t HandlerOffset);

  static constexpr int R_SCATTERED = 0x80000000; // From `<mach-o/reloc.h>`
  Emulator &Emu;
  uint64_t KernelAddr;
  std::map<std::string, std::unique_ptr<LoadedLibrary>> LLs;
  std::vector<const void *> Hdrs; // Registered headers
  std::set<uintptr_t> HdrSet;     // Set of registered headers for faster lookup
  std::vector<MachOHandler> Handlers; // Registered handlers
};

} // namespace ipasim

// !defined(IPASIM_DYNAMIC_LOADER_HPP)
#endif
