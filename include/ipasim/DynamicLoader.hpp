// DynamicLoader.hpp

#ifndef IPASIM_DYNAMIC_LOADER_HPP
#define IPASIM_DYNAMIC_LOADER_HPP

#include "ipasim/LoadedLibrary.hpp"

#include "ipasim/Common.hpp"
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
  DynamicLoader(uc_engine *UC);
  LoadedLibrary *load(const std::string &Path);
  void execute(LoadedLibrary *Lib);
  void *translate(void *Addr);
  void handleTrampoline(void *Ret, void **Args, void *Data);
  void callLoad(void *load, void *self, void *sel);
  template <typename... ArgTypes> void callBack(void *FP, ArgTypes... Args) {
    DynamicBackCaller(*this).callBack<ArgTypes...>(FP, Args...);
  }
  template <typename... ArgTypes> void *callBackR(void *FP, ArgTypes... Args) {
    return DynamicBackCaller(*this).callBackR<ArgTypes...>(FP, Args...);
  }

private:
  void callUC(uc_err Err);
  bool canSegmentsSlide(LIEF::MachO::Binary &Bin);
  void mapMemory(uint64_t Addr, uint64_t Size, uc_prot Perms);
  BinaryPath resolvePath(const std::string &Path);
  LoadedLibrary *loadMachO(const std::string &Path);
  LoadedLibrary *loadPE(const std::string &Path);
  static constexpr uint64_t alignToPageSize(uint64_t Addr) {
    return Addr & (-PageSize);
  }
  static constexpr uint64_t roundToPageSize(uint64_t Addr) {
    return alignToPageSize(Addr + PageSize - 1);
  }
  template <typename... Args>
  void call(const std::string &Lib, const std::string &Func,
            Args &&... Params) {
    LoadedLibrary *L = load(Lib);
    uint64_t Addr = L->findSymbol(*this, Func);
    auto *Ptr = reinterpret_cast<void (*)(Args...)>(Addr);
    Ptr(std::forward<Args>(Params)...);
  }
  static bool catchFetchProtMem(uc_engine *UC, uc_mem_type Type, uint64_t Addr,
                                int Size, int64_t Value, void *Data);
  bool handleFetchProtMem(uc_mem_type Type, uint64_t Addr, int Size,
                          int64_t Value);
  static void catchCode(uc_engine *UC, uint64_t Addr, uint32_t Size,
                        void *Data);
  void handleCode(uint64_t Addr, uint32_t Size);
  static bool catchMemWrite(uc_engine *UC, uc_mem_type Type, uint64_t Addr,
                            int Size, int64_t Value, void *Data);
  bool handleMemWrite(uc_mem_type Type, uint64_t Addr, int Size, int64_t Value);
  static bool catchMemUnmapped(uc_engine *UC, uc_mem_type Type, uint64_t Addr,
                               int Size, int64_t Value, void *Data);
  bool handleMemUnmapped(uc_mem_type Type, uint64_t Addr, int Size,
                         int64_t Value);
  // Finds only library, no symbol information is inspected. To do that, call
  // `inspect`.
  AddrInfo lookup(uint64_t Addr);
  AddrInfo inspect(uint64_t Addr);
  void execute(uint64_t Addr);
  void returnToKernel();
  void returnToEmulation();
  void continueOutsideEmulation(std::function<void()> Cont);
  DebugStream::Handler dumpAddr(uint64_t Addr);
  DebugStream::Handler dumpAddr(uint64_t Addr, const AddrInfo &AI);

  static constexpr int PageSize = 4096;
  static constexpr int R_SCATTERED = 0x80000000; // From `<mach-o/reloc.h>`.
  DebugLogger Log;
  uc_engine *const UC;
  std::map<std::string, std::unique_ptr<LoadedLibrary>> LIs;
  uint64_t KernelAddr;
  std::stack<uint32_t> LRs; // stack of return addresses
  bool Running; // `true` iff the Unicorn Engine is emulating some code
  bool Restart, Continue;
  std::function<void()> Continuation;

  class DynamicCaller {
  public:
    DynamicCaller(DynamicLoader &Dyld) : Dyld(Dyld), RegId(UC_ARM_REG_R0) {}
    void loadArg(size_t Size);
    bool call(bool Returns, uint32_t Addr);
    template <size_t N> void call0(bool Returns, uint32_t Addr) {
      if (Returns)
        call1<N, true>(Addr);
      else
        call1<N, false>(Addr);
    }
    template <size_t N, bool Returns> void call1(uint32_t Addr) {
      call2<N, Returns>(Addr);
    }
    template <size_t N, bool Returns, typename... ArgTypes>
    void call2(uint32_t Addr, ArgTypes... Params) {
      if constexpr (N > 0)
        call2<N - 1, Returns, ArgTypes..., uint32_t>(Addr, Params...,
                                                     Args[Args.size() - N]);
      else
        call3<Returns, ArgTypes...>(Addr, Params...);
    }
    template <bool Returns, typename... ArgTypes>
    void call3(uint32_t Addr, ArgTypes... Params) {
      if constexpr (Returns) {
        uint32_t RetVal =
            reinterpret_cast<uint32_t (*)(ArgTypes...)>(Addr)(Params...);
        Dyld.callUC(uc_reg_write(Dyld.UC, UC_ARM_REG_R0, &RetVal));
      } else
        reinterpret_cast<void (*)(ArgTypes...)>(Addr)(Params...);
    }

  private:
    DynamicLoader &Dyld;
    uc_arm_reg RegId;
    std::vector<uint32_t> Args;
  };

  class DynamicBackCaller {
  public:
    DynamicBackCaller(DynamicLoader &Dyld) : Dyld(Dyld) {}

    template <uc_arm_reg RegId> void pushArgs() {}
    template <uc_arm_reg RegId, typename... ArgTypes>
    void pushArgs(void *Arg, ArgTypes... Args) {
      using namespace ipasim;

      static_assert(UC_ARM_REG_R0 <= RegId && RegId <= UC_ARM_REG_R3,
                    "Callback has too many arguments.");
      Dyld.callUC(uc_reg_write(Dyld.UC, RegId, Arg));
      pushArgs<RegId + 1>(Args...);
    }
    template <typename... ArgTypes> void callBack(void *FP, ArgTypes... Args) {
      uint64_t Addr = reinterpret_cast<uint64_t>(FP);
      AddrInfo AI(Dyld.lookup(Addr));
      if (!dynamic_cast<LoadedDylib *>(AI.Lib)) {
        // Target load method is not inside any emulated Dylib, so it must be
        // native executable code and we can simply call it.
        reinterpret_cast<void (*)(ArgTypes...)>(FP)(Args...);
      } else {
        // Target load method is inside some emulated library.
        pushArgs<UC_ARM_REG_R0>(Args...);
        Dyld.execute(Addr);
      }
    }
    template <typename... ArgTypes>
    void *callBackR(void *FP, ArgTypes... Args) {
      callBack(FP, Args...);

      // Fetch return value.
      uint32_t R0;
      Dyld.callUC(uc_reg_read(Dyld.UC, UC_ARM_REG_R0, &R0));
      return reinterpret_cast<void *>(R0);
    }

  private:
    DynamicLoader &Dyld;
    std::vector<uint32_t> Args;
  };

  class TypeDecoder {
  public:
    TypeDecoder(DynamicLoader &Dyld, const char *T) : Dyld(Dyld), T(T) {}
    size_t getNextTypeSize();
    bool hasNext() { return *T; }

    static const size_t InvalidSize = -1;

  private:
    DynamicLoader &Dyld;
    const char *T;

    size_t getNextTypeSizeImpl();
  };
};

} // namespace ipasim

// !defined(IPASIM_DYNAMIC_LOADER_HPP)
#endif
