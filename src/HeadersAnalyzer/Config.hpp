// Config.hpp

#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstdint>

#include "Common.hpp"

constexpr LibType WarnUninterestingFunctions = LibType::None;
constexpr LibType ErrorUnimplementedFunctions = LibType::None;
constexpr LibType SumUnimplementedFunctions = LibType::Both;
constexpr bool VerboseClang = false;
constexpr bool IgnoreErrors = false;
constexpr bool Sample = false;
// TODO: Fix `TypeComparer` and then turn this on.
constexpr bool CompareTypes = false;

// !defined(CONFIG_HPP)
#endif
