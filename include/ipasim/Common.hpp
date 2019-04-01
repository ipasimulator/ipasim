// Common.hpp

#ifndef IPASIM_COMMON_HPP
#define IPASIM_COMMON_HPP

#include <cstdint>
#include <string>

namespace ipasim {

// Prefix and postfix operators
#define prefix(op) &operator op()
#define postfix(op) operator op(int)

// =============================================================================
// Enums
// =============================================================================

// Inspired by <https://stackoverflow.com/a/23152590/9080566>.
template <typename T> constexpr T operator~(T a) { return (T) ~(int)a; }
template <typename T> constexpr T operator|(T a, T b) {
  return (T)((int)a | (int)b);
}
template <typename T> constexpr bool operator&(T a, T b) {
  return (T)((int)a & (int)b) == b;
}
template <typename T> constexpr T operator^(T a, T b) {
  return (T)((int)a ^ (int)b);
}
template <typename T> constexpr T operator+(T a, int b) {
  return (T)((int)a + b);
}
template <typename T> constexpr T operator++(T &a, int /* postfix */) {
  return (T)(((int &)a)++);
}
template <typename T> constexpr T &operator|=(T &a, T b) {
  return (T &)((int &)a |= (int)b);
}
template <typename T> constexpr T &operator&=(T &a, T b) {
  return (T &)((int &)a &= (int)b);
}
template <typename T> constexpr T &operator^=(T &a, T b) {
  return (T &)((int &)a ^= (int)b);
}
template <typename T> constexpr T &operator+=(T &a, int b) {
  return (T &)((int &)a += b);
}

// =============================================================================
// Conversions
// =============================================================================

inline const uint8_t *bytes(const void *Ptr) {
  return reinterpret_cast<const uint8_t *>(Ptr);
}
template <typename T> inline std::string to_hex_string(T Value) {
  std::stringstream SS;
  SS << std::hex << Value;
  return SS.str();
}

// =============================================================================
// Strings
// =============================================================================

// `constexpr` `strlen`. Usage: `constexpr size_t len = length(ConstExprVar);`.
size_t constexpr length(const char *S) { return *S ? 1 + length(S + 1) : 0; }
struct ConstexprString {
  constexpr ConstexprString(const char *S) : S(S), Len(length(S)) {}
  ConstexprString(const std::string &S) : S(S.data()), Len(S.length()) {}

  const char *S;
  size_t Len;
};
inline bool startsWith(const std::string &S, ConstexprString Prefix) {
  return !S.compare(0, Prefix.Len, Prefix.S);
}
inline bool endsWith(const std::string &S, ConstexprString Suffix) {
  return !S.compare(S.length() - Suffix.Len, Suffix.Len, Suffix.S);
}

} // namespace ipasim

// !defined(IPASIM_COMMON_HPP)
#endif
