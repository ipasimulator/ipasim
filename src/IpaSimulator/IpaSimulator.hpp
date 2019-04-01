// IpaSimulator.hpp

#ifndef IPASIM_IPA_SIMULATOR_HPP
#define IPASIM_IPA_SIMULATOR_HPP

#include "DynamicLoader.hpp"

#include <string>
#include <unicorn/unicorn.h>

namespace ipasim {

inline void callUCSimple(uc_err Err) {
  // TODO: Throw better exceptions.
  if (Err != UC_ERR_OK)
    throw "unicorn error";
}

class IpaSimulator {
public:
  IpaSimulator() : UC(initUC()), Dyld(UC) {}
  ~IpaSimulator() { callUCSimple(uc_close(UC)); }

  uc_engine *UC;
  DynamicLoader Dyld;
  std::string MainBinary;

private:
  static uc_engine *initUC() {
    uc_engine *UC;
    callUCSimple(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &UC));
    return UC;
  }
};

extern IpaSimulator IpaSim;

} // namespace ipasim

// !defined(IPASIM_IPA_SIMULATOR_HPP)
#endif
