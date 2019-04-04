// IpaSimulator.hpp

#ifndef IPASIM_IPA_SIMULATOR_HPP
#define IPASIM_IPA_SIMULATOR_HPP

#include "ipasim/DynamicLoader.hpp"
#include "ipasim/Logger.hpp"

#include <string>
#include <unicorn/unicorn.h>

namespace ipasim {

class IpaSimulator {
public:
  DynamicLoader Dyld;
  std::string MainBinary;
};

extern IpaSimulator IpaSim;
extern DebugLogger Log;

} // namespace ipasim

// !defined(IPASIM_IPA_SIMULATOR_HPP)
#endif
