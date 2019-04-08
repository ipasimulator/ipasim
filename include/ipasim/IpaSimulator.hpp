// IpaSimulator.hpp

#ifndef IPASIM_IPA_SIMULATOR_HPP
#define IPASIM_IPA_SIMULATOR_HPP

#include "ipasim/DynamicLoader.hpp"
#include "ipasim/Emulator.hpp"
#include "ipasim/Logger.hpp"
#include "ipasim/SysTranslator.hpp"

#include <string>
#include <unicorn/unicorn.h>

namespace ipasim {

class IpaSimulator {
public:
  IpaSimulator();

  Emulator Emu;
  DynamicLoader Dyld;
  std::string MainBinary;
  SysTranslator Sys;
};

extern IpaSimulator IpaSim;
extern DebugLogger Log;

} // namespace ipasim

// !defined(IPASIM_IPA_SIMULATOR_HPP)
#endif
