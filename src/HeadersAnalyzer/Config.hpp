// Config.hpp

#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstdint>

enum class LibType { None = 0, Dylib = 0x1, DLL = 0x2, Both = 0x3 };

constexpr bool operator&(LibType Value, LibType Flag) {
  return ((uint32_t)Value & (uint32_t)Flag) == (uint32_t)Flag;
}

constexpr LibType WarnUninterestingFunctions = LibType::None;
constexpr LibType ErrorUnimplementedFunctions = LibType::None;
constexpr LibType SumUnimplementedFunctions = LibType::Both;
constexpr bool OutputLLVMIR = false;
constexpr bool VerboseClang = false;
constexpr bool IgnoreErrors = false;
constexpr bool Sample = true;

// !defined(CONFIG_HPP)
#endif
