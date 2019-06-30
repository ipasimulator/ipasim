// WrapperIndex.hpp: Definition of struct `WrapperIndex`.

#ifndef IPASIM_WRAPPER_INDEX_HPP
#define IPASIM_WRAPPER_INDEX_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ipasim {

// A helper data structure generated into wrapper DLLs by `HeadersAnalyzer`.
struct WrapperIndex {
  WrapperIndex();

  std::vector<std::string> Dylibs;
  // Map from original DLL RVA to wrapper Dylib index
  std::map<uint32_t, uint32_t> Map;
};

} // namespace ipasim

// !defined(IPASIM_WRAPPER_INDEX_HPP)
#endif
