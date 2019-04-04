// Emulator.hpp

#ifndef IPASIM_EMULATOR_HPP
#define IPASIM_EMULATOR_HPP

#include <unicorn/unicorn.h>
#include <utility>

namespace ipasim {

class DynamicLoader;

class Emulator {
public:
  Emulator(DynamicLoader &Dyld) : UC(initUC()), Dyld(Dyld) {}
  Emulator(const Emulator &) = delete;
  Emulator(Emulator &&E) : UC(nullptr), Dyld(E.Dyld) { std::swap(UC, E.UC); }
  ~Emulator();

  uint32_t readReg(uc_arm_reg RegId);
  void writeReg(uc_arm_reg RegId, uint32_t Value);
  void mapMemory(uint64_t Addr, uint64_t Size, uc_prot Perms);
  void start(uint64_t Addr);
  void stop();
  template <typename F>
  void hook(uc_hook_type Type, F *Handler, void *Instance) {
    hook(Type, reinterpret_cast<void *>(Handler), Instance);
  }
  void hook(uc_hook_type Type, void *Handler, void *Instance);

private:
  uc_engine *UC;
  DynamicLoader &Dyld;

  static uc_engine *initUC();
  static void callUCStatic(uc_err Err);
  void callUC(uc_err Err);
};

} // namespace ipasim

// !defined(IPASIM_EMULATOR_HPP)
#endif
