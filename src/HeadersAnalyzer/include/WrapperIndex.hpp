// WrapperIndex.hpp

#include <cstdint>
#include <map>
#include <vector>

struct WrapperIndex {
  WrapperIndex();

  std::vector<std::string> Dylibs;
  // original DLL RVA -> wrapper Dylib index
  std::map<uint32_t, uint32_t> Map;
};
