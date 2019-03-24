#include <LIEF/LIEF.hpp>
#include <Windows.h>
#include <functional>
#include <stack>
#include <string>
#include <unicorn/unicorn.h>

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

struct BinaryPath {
  std::string Path;
  bool Relative; // true iff `Path` is relative to install dir
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
  template <typename... ArgTypes> bool callBack(void *FP, ArgTypes... Args) {
    return DynamicBackCaller(*this).callBack<ArgTypes...>(FP, Args...);
  }
  template <typename... ArgTypes> void *callBackR(void *FP, ArgTypes... Args) {
    return DynamicBackCaller(*this).callBackR<ArgTypes...>(FP, Args...);
  }

private:
  void error(const std::string &Msg, bool AppendLastError = false);
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

  static constexpr int PageSize = 4096;
  static constexpr int R_SCATTERED = 0x80000000; // From `<mach-o/reloc.h>`.
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
    int RegId; // uc_arm_reg
    std::vector<uint32_t> Args;
  };

  class DynamicBackCaller {
  public:
    DynamicBackCaller(DynamicLoader &Dyld) : Dyld(Dyld), RegId(UC_ARM_REG_R0) {}

    bool pushArgs() { return true; }
    template <typename... ArgTypes> bool pushArgs(void *Arg, ArgTypes... Args) {
      if (RegId > UC_ARM_REG_R3) {
        // TODO: This should happen at compile-time.
        Dyld.error("callback has too many arguments");
        return false;
      }
      Dyld.callUC(uc_reg_write(Dyld.UC, RegId++, Arg));
      return pushArgs(Args...);
    }
    template <typename... ArgTypes> bool callBack(void *FP, ArgTypes... Args) {
      uint64_t Addr = reinterpret_cast<uint64_t>(FP);
      AddrInfo AI(Dyld.lookup(Addr));
      if (!dynamic_cast<LoadedDylib *>(AI.Lib)) {
        // Target load method is not inside any emulated Dylib, so it must be
        // native executable code and we can simply call it.
        reinterpret_cast<void (*)(ArgTypes...)>(FP)(Args...);
        return true;
      } else {
        // Target load method is inside some emulated library.

        if (!pushArgs(Args...))
          return false;

        Dyld.execute(Addr);
        return true;
      }
    }
    template <typename... ArgTypes>
    void *callBackR(void *FP, ArgTypes... Args) {
      if (!callBack(FP, Args...))
        return nullptr;

      // Fetch return value.
      uint32_t R0;
      Dyld.callUC(uc_reg_read(Dyld.UC, UC_ARM_REG_R0, &R0));
      return reinterpret_cast<void *>(R0);
    }

  private:
    DynamicLoader &Dyld;
    int RegId; // uc_arm_reg
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
