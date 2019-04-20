// HeadersAnalyzer/Config.hpp

#ifndef IPASIM_HEADERS_ANALYZER_CONFIG_HPP
#define IPASIM_HEADERS_ANALYZER_CONFIG_HPP

#include "ipasim/Common.hpp"
#include "ipasim/HAContext.hpp"

#include <cstdint>

constexpr ipasim::LibType WarnUninterestingFunctions = ipasim::LibType::None;
constexpr ipasim::LibType ErrorUnimplementedFunctions = ipasim::LibType::None;
constexpr ipasim::LibType SumUnimplementedFunctions = ipasim::LibType::Both;
constexpr bool VerboseClang = false;
constexpr bool IgnoreErrors = false;
constexpr bool Sample = true;
// TODO: Fix `TypeComparer` and then turn this on.
constexpr bool CompareTypes = false;

// !defined(IPASIM_HEADERS_ANALYZER_CONFIG_HPP)
#endif
