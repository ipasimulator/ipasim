// SysTranslator.hpp

#ifndef IPASIM_SYS_TRANSLATOR_HPP
#define IPASIM_SYS_TRANSLATOR_HPP

#include "ipasim/DynamicLoader.hpp"
#include "ipasim/Emulator.hpp"
#include "ipasim/LoadedLibrary.hpp"

#include <ffi.h>

namespace ipasim {

class SysTranslator {
public:
  SysTranslator(DynamicLoader &Dyld, Emulator &Emu)
      : Dyld(Dyld), Emu(Emu), Running(false), Restart(false), Continue(false),
        RestartFromLRs(false) {}
  void execute(LoadedLibrary *Lib);
  void execute(uint64_t Addr);
  void *translate(void *Addr);
  void *translate(void *Addr, size_t ArgC, bool Returns = false);
  template <typename... Args>
  void call(const std::string &Lib, const std::string &Func,
            Args &&... Params) {
    LoadedLibrary *L = Dyld.load(Lib);
    uint64_t Addr = L->findSymbol(Dyld, Func);
    auto *Ptr = reinterpret_cast<void (*)(Args...)>(Addr);
    Ptr(std::forward<Args>(Params)...);
  }
  template <typename... ArgTys> void callBack(void *FP, ArgTys... Args);
  template <typename... ArgTys> void *callBackR(void *FP, ArgTys... Args);

private:
  bool handleFetchProtMem(uc_mem_type Type, uint64_t Addr, int Size,
                          int64_t Value);
  void handleCode(uint64_t Addr, uint32_t Size);
  bool handleMemWrite(uc_mem_type Type, uint64_t Addr, int Size, int64_t Value);
  bool handleMemUnmapped(uc_mem_type Type, uint64_t Addr, int Size,
                         int64_t Value);
  void *createTrampoline(void *Addr, size_t ArgC, bool Returns);
  void handleTrampoline(void *Ret, void **Args, void *Data);
  static void handleTrampolineStatic(ffi_cif *, void *Ret, void **Args,
                                     void *Data);
  void returnToKernel();
  void returnToEmulation();
  void continueOutsideEmulation(std::function<void()> &&Cont);

  DynamicLoader &Dyld;
  Emulator &Emu;
  std::stack<uint32_t> LRs; // stack of return addresses
  bool Running; // `true` iff the Unicorn Engine is emulating some code
  bool Restart, Continue, RestartFromLRs;
  std::function<void()> Continuation;
};

class DynamicCaller {
public:
  DynamicCaller(Emulator &Emu)
      : Emu(Emu), RegId(UC_ARM_REG_R0), SP(Emu.readReg(UC_ARM_REG_SP)) {}
  void loadArg(size_t Size);
  bool call(bool Returns, uint32_t Addr);

private:
  template <size_t N> void call(bool Returns, uint32_t Addr) {
    if (Returns)
      call<N, N, true>(Addr);
    else
      call<N, N, false>(Addr);
  }
  template <size_t N, size_t C, bool Returns, typename... ArgTypes>
  void call(uint32_t Addr, ArgTypes... Params) {
    if constexpr (N > 0)
      call<N - 1, C, Returns, ArgTypes..., uint32_t>(Addr, Params...,
                                                     Args[C - N]);
    else
      call<Returns, ArgTypes...>(Addr, Params...);
  }
  template <bool Returns, typename... ArgTypes>
  void call(uint32_t Addr, ArgTypes... Params) {
    if constexpr (Returns) {
      uint32_t RetVal =
          reinterpret_cast<uint32_t (*)(ArgTypes...)>(Addr)(Params...);
      Emu.writeReg(UC_ARM_REG_R0, RetVal);
    } else
      reinterpret_cast<void (*)(ArgTypes...)>(Addr)(Params...);
  }

  Emulator &Emu;
  uc_arm_reg RegId;
  uint32_t SP;
  std::vector<uint32_t> Args;
};

class DynamicBackCaller {
public:
  DynamicBackCaller(DynamicLoader &Dyld, Emulator &Emu, SysTranslator &Sys)
      : Dyld(Dyld), Emu(Emu), Sys(Sys) {}

  template <typename... ArgTypes> void callBack(void *FP, ArgTypes... Args) {
    uint64_t Addr = reinterpret_cast<uint64_t>(FP);
    LibraryInfo LI(Dyld.lookup(Addr));
    if (!LI.Lib || LI.Lib->isDLL()) {
      // Target load method is not inside any emulated Dylib, so it must be
      // native executable code and we can simply call it.
      reinterpret_cast<void (*)(ArgTypes...)>(FP)(Args...);
    } else {
      // Target load method is inside some emulated library.
      pushArgs<UC_ARM_REG_R0>(Args...);
      Sys.execute(Addr);
    }
  }
  template <typename... ArgTypes> void *callBackR(void *FP, ArgTypes... Args) {
    callBack(FP, Args...);

    // Fetch return value.
    return reinterpret_cast<void *>(Emu.readReg(UC_ARM_REG_R0));
  }

private:
  template <uc_arm_reg RegId> void pushArgs() {}
  template <uc_arm_reg RegId, typename... ArgTypes>
  void pushArgs(void *Arg, ArgTypes... Args) {
    using namespace ipasim;

    static_assert(UC_ARM_REG_R0 <= RegId && RegId <= UC_ARM_REG_R3,
                  "Callback has too many arguments.");
    Emu.writeReg(RegId, reinterpret_cast<uint32_t>(Arg));
    pushArgs<RegId + 1>(Args...);
  }

  DynamicLoader &Dyld;
  Emulator &Emu;
  SysTranslator &Sys;
  std::vector<uint32_t> Args;
};

class TypeDecoder {
public:
  TypeDecoder(const char *T) : T(T) {}
  size_t getNextTypeSize();
  bool hasNext() { return *T; }

  static const size_t InvalidSize = -1;

private:
  const char *T;

  size_t getNextTypeSizeImpl();
};

template <typename... ArgTys>
inline void SysTranslator::callBack(void *FP, ArgTys... Args) {
  DynamicBackCaller(Dyld, Emu, *this).callBack<ArgTys...>(FP, Args...);
}
template <typename... ArgTys>
inline void *SysTranslator::callBackR(void *FP, ArgTys... Args) {
  return DynamicBackCaller(Dyld, Emu, *this).callBackR<ArgTys...>(FP, Args...);
}

} // namespace ipasim

// !defined(IPASIM_SYS_TRANSLATOR_HPP)
#endif
