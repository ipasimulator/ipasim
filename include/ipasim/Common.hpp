// Common.hpp

#ifndef IPASIM_COMMON_HPP
#define IPASIM_COMMON_HPP

#include <cstdint>
#include <string>

namespace ipasim {

// Binary operators on enums. Inspired by
// <https://stackoverflow.com/a/23152590/9080566>.
template <typename T> inline T operator~(T a) { return (T) ~(int)a; }
template <typename T> inline T operator|(T a, T b) {
  return (T)((int)a | (int)b);
}
template <typename T> inline T operator&(T a, T b) {
  return (T)((int)a & (int)b);
}
template <typename T> inline T operator^(T a, T b) {
  return (T)((int)a ^ (int)b);
}
template <typename T> inline T &operator|=(T &a, T b) {
  return (T &)((int &)a |= (int)b);
}
template <typename T> inline T &operator&=(T &a, T b) {
  return (T &)((int &)a &= (int)b);
}
template <typename T> inline T &operator^=(T &a, T b) {
  return (T &)((int &)a ^= (int)b);
}

// Conversions
inline const uint8_t *bytes(const void *Ptr) {
  return reinterpret_cast<const uint8_t *>(Ptr);
}
template <typename T> inline std::string to_hex_string(T Value) {
  std::stringstream SS;
  SS << std::hex << Value;
  return SS.str();
}

// Strings
inline bool startsWith(const std::string &S, const std::string &Prefix) {
  return !S.compare(0, Prefix.length(), Prefix);
}
inline bool endsWith(const std::string &S, const std::string &Suffix) {
  return !S.compare(S.length() - Suffix.length(), Suffix.length(), Suffix);
}

} // namespace ipasim

// !defined(IPASIM_COMMON_HPP)
#endif
