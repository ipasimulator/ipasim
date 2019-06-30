// HeadersAnalyzer/Config.hpp: Contains configuration switches for tool
// `HeadersAnalyzer`.

#ifndef IPASIM_HEADERS_ANALYZER_CONFIG_HPP
#define IPASIM_HEADERS_ANALYZER_CONFIG_HPP

#include "ipasim/Common.hpp"
#include "ipasim/HAContext.hpp"

#include <cstdint>

namespace ipasim {

#ifndef IPASIM_DEBUG
#define IPASIM_DEBUG 0
#endif

constexpr ipasim::LibType WarnUninterestingFunctions = ipasim::LibType::None;
constexpr ipasim::LibType ErrorUnimplementedFunctions = ipasim::LibType::None;
constexpr ipasim::LibType SumUnimplementedFunctions = ipasim::LibType::Both;
constexpr bool VerboseClang = false;
constexpr bool IgnoreErrors = false;
constexpr bool Sample = IPASIM_DEBUG && true;
// TODO: Fix `TypeComparer` and then turn this on.
constexpr bool CompareTypes = false;

} // namespace ipasim

// !defined(IPASIM_HEADERS_ANALYZER_CONFIG_HPP)
#endif
