// WrapperIndex.hpp

#ifndef IPASIM_WRAPPER_INDEX_HPP
#define IPASIM_WRAPPER_INDEX_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ipasim {

struct WrapperIndex {
  WrapperIndex();

  std::vector<std::string> Dylibs;
  // original DLL RVA -> wrapper Dylib index
  std::map<uint32_t, uint32_t> Map;
};

} // namespace ipasim

// !defined(IPASIM_WRAPPER_INDEX_HPP)
#endif
