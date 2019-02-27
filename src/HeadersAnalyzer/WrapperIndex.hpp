// WrapperIndex.hpp

#include <cstdint>
#include <map>
#include <vector>

struct WrapperIndex {
  WrapperIndex();

  std::vector<std::string> Dylibs;
  // original DLL RVAs -> wrapper Dylib index and RVA
  std::map<uint32_t, std::pair<uint32_t, uint32_t>> Map;
};
